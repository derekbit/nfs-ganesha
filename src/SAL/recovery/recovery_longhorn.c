// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "config.h"
#include "log.h"
#include "nfs_core.h"
#include "nfs4.h"
#include "sal_functions.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include "bsd-base64.h"
#include "client_mgr.h"
#include "fsal.h"
#include "recovery_fs.h"
#include <libgen.h>
#include <curl/curl.h>

typedef enum {
	HTTP_GET = 0,
	HTTP_POST,
	HTTP_PUT,
	HTTP_DELETE,
} HTTP_METHOD;

struct http_result {
	void *memory;
	size_t size;
};


static char v4_recov_version[NAME_MAX];

static size_t callback_write_result(void *contents, size_t size, size_t nmemb, void *userp) {
	char *buf = NULL;
	size_t real_size = size * nmemb;

	if (contents != NULL && userp != NULL) {
		struct http_result *mem = (struct http_result *) userp;
		buf = realloc(mem->memory, mem->size + real_size + 1);
		if (buf) {
			mem->memory = buf;
			memcpy(&(((unsigned char *)mem->memory)[mem->size]), contents, real_size);
			mem->size += real_size;
			return real_size;
		}
	}
	return 0;
}

static int http_call(HTTP_METHOD method, const char *url, char *payload, size_t payload_size, char **output, size_t *output_size) {
	int result = -1;
	struct http_result buffer = {.memory = NULL, .size = 0};
	CURL *handle = NULL;
	CURLcode curl_result = 0;
	struct curl_slist *curl_headers = NULL;
	char *encoded_url = NULL;
	long http_code = 0;

	if (method < HTTP_GET || method > HTTP_DELETE) {
		LogEvent(COMPONENT_CLIENTID, "invalid method: (%d)", method);
		goto error;
	}

	if (!url) {
		LogEvent(COMPONENT_CLIENTID, "url is NULL");
		goto error;
	}

	/* Initialize CURL handle */
	handle = curl_easy_init();
	if (!handle) {
		LogEvent(COMPONENT_CLIENTID, "failed to initialize CURL");
		goto error;
	}
	
	/* Set CURL options */
	curl_result = curl_easy_setopt(handle, CURLOPT_URL, url);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	curl_result = curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	curl_result = curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, callback_write_result);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	curl_result = curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void *)&buffer);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	curl_result = curl_easy_setopt(handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	switch (method) {
		case HTTP_GET:
			curl_result = curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}
			break;
		case HTTP_POST:
			curl_result = curl_easy_setopt(handle, CURLOPT_POST, 1L);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			curl_result = curl_easy_setopt(handle, CURLOPT_POSTFIELDS, payload);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			curl_result = curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, payload_size);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			break;
		case HTTP_PUT:
			curl_result = curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "PUT");
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			curl_result = curl_easy_setopt(handle, CURLOPT_POSTFIELDS, payload);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			curl_result = curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, payload_size);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			break;
		case HTTP_DELETE:
			curl_result = curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "DELETE");
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}
	}

	/* Set HTTP headers */
	curl_headers = curl_slist_append(curl_headers, "Accept: application/json");
	if (!curl_headers) {
		LogEvent(COMPONENT_CLIENTID, "failed to construct CURL headers");
		goto error;
	}

	curl_headers = curl_slist_append(curl_headers, "Content-Type: application/json; charset=utf-8");
	if (!curl_headers) {
		LogEvent(COMPONENT_CLIENTID, "failed to construct CURL headers");
		goto error;
	}

	curl_headers = curl_slist_append(curl_headers, "Connection: close");
	if (!curl_headers) {
		LogEvent(COMPONENT_CLIENTID, "failed to construct CURL headers");
		goto error;
	}

	curl_result = curl_easy_setopt(handle, CURLOPT_HTTPHEADER, curl_headers);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "failed to set CURL headers: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	/* Make HTTP request */
	curl_result = curl_easy_perform(handle);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "failed to perform CURL operation: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	curl_result = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_code);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "failed to perform CURL operation: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	if (http_code != 200) {
		LogEvent(COMPONENT_CLIENTID, "HTTP error: %ld", http_code);
		goto error;
	}

	*output = buffer.memory;
	*output_size = buffer.size;
	result = 0;
error:
	if (result != 0) {
		if (buffer.memory != NULL) {
			free(buffer.memory);
			buffer.memory = NULL;
			*output = NULL;
			*output_size = 0;
		}
	}
	if (curl_headers != NULL)
		curl_slist_free_all(curl_headers);
	if (encoded_url != NULL)
		free(encoded_url);
	if (handle != NULL)
		curl_easy_cleanup(handle);

	return result;
}

static int longhorn_recov_init(void)
{
	return 0;
}

static void longhorn_recov_end_grace(void)
{
	return;
}

static void longhorn_add_clid(nfs_client_id_t *clientid)
{
}


static void longhorn_rm_clid(nfs_client_id_t *clientid)
{
}


static void longhorn_read_recov_clids(nfs_grace_start_t *gsp,
				  add_clid_entry_hook add_clid_entry,
				  add_rfh_entry_hook add_rfh_entry)
{
}

static void longhorn_add_revoke_fh(nfs_client_id_t *delr_clid, nfs_fh4 *delr_handle)
{

}

static struct nfs4_recovery_backend longhorn_backend = {
	.recovery_init = longhorn_recov_init,
	.end_grace = longhorn_recov_end_grace,
	.recovery_read_clids = longhorn_read_recov_clids,
	.add_clid = longhorn_add_clid,
	.rm_clid = longhorn_rm_clid,
	.add_revoke_fh = longhorn_add_revoke_fh,
};

void longhorn_backend_init(struct nfs4_recovery_backend **backend)
{
	*backend = &longhorn_backend;
}
