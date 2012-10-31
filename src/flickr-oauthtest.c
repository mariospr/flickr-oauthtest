/*
 * flickr-oauthtest.c -- Simple test application for checking Flickr's
 * OAauth based authentication system (only one after July 21st, 2012)
 *
 * Copyright (C) 2012 Mario Sanchez Prada
 * Authors: Mario Sanchez Prada <mario@mariospr.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 * Parts of this file based on code from Igalia S.L. and RedHat Inc,
 * licensed as LGPLv2.1 and LGPLv2, respectively. See details below.
 */
#include <config.h>

#include <gcrypt.h>
#include <glib.h>
#include <libsoup/soup.h>
#include <string.h>

#define FLICKR_REQUEST_TOKEN_OAUTH_URL "http://www.flickr.com/services/oauth/request_token"
#define FLICKR_ACCESS_TOKEN_OAUTH_URL "http://www.flickr.com/services/oauth/access_token"
#define FLICKR_API_BASE_URL   "http://api.flickr.com/services/rest"

#define OAUTH_CALLBACK_URL "oob"
#define OAUTH_SIGNATURE_METHOD "HMAC-SHA1"
#define OAUTH_VERSION "1.0"

#define CONSUMER_KEY "01234567890123456789012345678901"
#define CONSUMER_SECRET "0123456789abcdef"

#define DEBUG(...) g_debug (__VA_ARGS__)

static gchar *
_encode_uri                             (const gchar *uri)
{
  return soup_uri_encode (uri, "%!*'();:@&=+$,/?#[] ");
}

/* This function is based in sign_string() from Grilo's Vimeo plugin,
   licensed as LGPLv2.1 (Copyright 2010, 2011 Igalia S.L.) */
static gchar *
_sign_string                            (const gchar *message,
                                         const gchar *signing_key)
{
  gchar *signature = NULL;
  gchar *encoded_signature = NULL;
  gcry_md_hd_t digest_obj;
  unsigned char *hmac_digest;
  guint digest_len;

  gcry_md_open(&digest_obj, GCRY_MD_SHA1, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
  gcry_md_setkey(digest_obj, signing_key, strlen (signing_key));
  gcry_md_write (digest_obj, message, strlen (message));
  gcry_md_final (digest_obj);
  hmac_digest = gcry_md_read (digest_obj, 0);

  digest_len = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
  signature = g_base64_encode (hmac_digest, digest_len);

  gcry_md_close (digest_obj);

  encoded_signature = _encode_uri (signature);
  g_free(signature);

  return encoded_signature;
}

static GHashTable *
_get_params_table_from_valist           (const gchar *first_param,
                                         va_list      args)
{
  GHashTable *table = NULL;
  gchar *p = NULL;
  gchar *v = NULL;

  g_return_val_if_fail (first_param != NULL, NULL);

  table = g_hash_table_new_full (g_str_hash, g_str_equal,
                                 (GDestroyNotify)g_free,
                                 (GDestroyNotify)g_free);
  /* Fill the hash table */
  for (p = (gchar *) first_param; p; p = va_arg (args, gchar*))
    {
      v = va_arg (args, gchar*);

      /* Ignore parameter with no value */
      if (v != NULL)
        g_hash_table_insert (table, g_strdup (p), g_strdup (v));
      else
        DEBUG ("Missing value for %s. Ignoring parameter.", p);
    }

  return table;
}

/* This function is based in append_form_encoded() from libsoup's
   SoupForm, licensed as LGPLv2 (Copyright 2008 Red Hat, Inc.) */
static gchar *
_encode_query_value (const char *value)
{
  GString *result = NULL;
  const unsigned char *str = NULL;

  result = g_string_new ("");
  str = (const unsigned char *) value;

  while (*str) {
    if (*str == ' ') {
      g_string_append_c (result, '+');
      str++;
    } else if (!g_ascii_isalnum (*str))
      g_string_append_printf (result, "%%%02X", (int)*str++);
    else
      g_string_append_c (result, *str++);
  }

  return g_string_free (result, FALSE);
}

static gboolean
_should_encode_key                      (const gchar *key,
                                         gboolean     old_auth_api)
{
  if (old_auth_api)
    return g_strcmp0 (key, "api_key") && g_strcmp0 (key, "auth_token")
      && g_strcmp0 (key, "method") && g_strcmp0 (key, "frob");

  /* Using the new OAuth-based authentication API */
  return g_strcmp0 (key, "oauth_token") && g_strcmp0 (key, "oauth_verifier")
    && g_strcmp0 (key, "oauth_consumer_key") && g_strcmp0 (key, "oauth_signature_method")
    && g_strcmp0 (key, "oauth_version") && g_strcmp0 (key, "oauth_signature")
    && g_strcmp0 (key, "oauth_callback") && g_strcmp0 (key, "method");
}

static gchar *
_get_signed_query_with_params           (const gchar      *api_sig,
                                         GHashTable       *params_table,
                                         gboolean          old_auth_api)
{
  GList *keys = NULL;
  gchar *retval = NULL;

  g_return_val_if_fail (params_table != NULL, NULL);
  g_return_val_if_fail (api_sig != NULL, NULL);

  /* Get ownership of the table */
  g_hash_table_ref (params_table);

  /* Get a list of keys */
  keys = g_hash_table_get_keys (params_table);
  if (keys != NULL)
    {
      gchar **url_params_array = NULL;
      GList *k = NULL;
      gint i = 0;

      /* Build gchar** arrays for building the final
         string to be used as the list of GET params */
      url_params_array = g_new0 (gchar*, g_list_length (keys) + 2);

      /* Fill arrays */
      for (k = keys; k; k = g_list_next (k))
        {
          gchar *key = (gchar*) k->data;
          gchar *value = g_hash_table_lookup (params_table, key);
          gchar *actual_value = NULL;

          /* Do not encode basic pairs key-value */
          if (_should_encode_key (key, old_auth_api))
            actual_value = _encode_query_value (value);
          else
            actual_value = g_strdup (value);

          url_params_array[i++] = g_strdup_printf ("%s=%s", key, actual_value);
          g_free (actual_value);
        }

      /* Add those to the params array (space previously reserved) */
      url_params_array[i] = g_strdup_printf (old_auth_api
                                             ? "api_sig=%s"
                                             : "oauth_signature=%s",
                                             api_sig);
      /* Build the signed query */
      retval = g_strjoinv ("&", url_params_array);

      /* Free */
      g_strfreev (url_params_array);
    }
  g_list_free (keys);
  g_hash_table_unref (params_table);

  return retval;
}

static gchar *
_get_params_str_for_signature           (GHashTable  *params_table,
                                         const gchar *signing_key,
                                         gboolean old_auth_api)
{
  GList *keys = NULL;
  gchar **params_str_array = NULL;
  gchar *params_str = NULL;
  GList *k = NULL;
  gint i = 0;

  /* Get a list of keys */
  keys = g_hash_table_get_keys (params_table);
  if (!keys)
    return NULL;

  /* Sort the list */
  keys = g_list_sort (keys, (GCompareFunc) g_strcmp0);

  /* Build gchar** arrays for building the signature string */
  if (old_auth_api)
    {
      params_str_array = g_new0 (gchar*, (2 * g_list_length (keys)) + 2);
      params_str_array[i++] = g_strdup (signing_key);
    }
  else
    params_str_array = g_new0 (gchar*, g_list_length (keys) + 1);

  /* Fill arrays */
  for (k = keys; k; k = g_list_next (k))
    {
      const gchar *key = (gchar*) k->data;
      const gchar *value = g_hash_table_lookup (params_table, key);

      if (old_auth_api)
        {
          params_str_array[i++] = g_strdup (key);
          params_str_array[i++] = g_strdup (value);
        }
      else
        params_str_array[i++] = g_strdup_printf ("%s=%s", key, value);
    }
  params_str_array[i] = NULL;

  params_str = g_strjoinv (old_auth_api ? NULL : "&", params_str_array);
  g_strfreev (params_str_array);

  g_list_free (keys);

  return params_str;
}

static gchar *
_calculate_api_signature                (const gchar *url,
                                         const gchar *params_str,
                                         const gchar *signing_key,
                                         gboolean old_auth_api)
{
  gchar *base_string = NULL;
  gchar *encoded_params = NULL;
  gchar *encoded_url = NULL;
  gchar *api_sig = NULL;

  if (!params_str)
    return NULL;

  if (old_auth_api)
    return g_compute_checksum_for_string (G_CHECKSUM_MD5, params_str, -1);

  /* Using the new OAuth-based authentication API */
  encoded_url = _encode_uri (url);
  encoded_params = _encode_uri (params_str);

  base_string = g_strdup_printf ("GET&%s&%s", encoded_url, encoded_params);
  g_free (encoded_url);
  g_free (encoded_params);

  api_sig = _sign_string (base_string, signing_key);
  g_free (base_string);

  return api_sig;
}

gchar *
_get_api_signature_from_hash_table      (const gchar *url,
                                         GHashTable  *params_table,
                                         const gchar *signing_key,
                                         gboolean old_auth_api)
{
  gchar *api_sig = NULL;
  gchar *params_str = NULL;

  g_return_val_if_fail (params_table != NULL, NULL);

  /* Get the signature string and calculate the api_sig value */
  params_str = _get_params_str_for_signature (params_table, signing_key, old_auth_api);
  api_sig = _calculate_api_signature (url, params_str, signing_key, old_auth_api);
  g_free (params_str);

  return api_sig;
}

gchar *
_get_signed_url                       (const gchar *url,
                                       const gchar *signing_key,
                                       gboolean old_auth_api,
                                       const gchar *first_param,
                                       ... )
{
  va_list args;
  GHashTable *table = NULL;
  gchar *signed_query = NULL;
  gchar *api_sig = NULL;
  gchar *retval = NULL;

  g_return_val_if_fail (signing_key != NULL, NULL);
  g_return_val_if_fail (first_param != NULL, NULL);

  va_start (args, first_param);

  /* Get the hash table for the params */
  table = _get_params_table_from_valist (first_param, args);

  if (!old_auth_api)
    {
      gchar *timestamp = NULL;
      gchar *random_str = NULL;
      gchar *nonce = NULL;

      /* Add mandatory parameters to the hash table */
      timestamp = g_strdup_printf ("%d", (gint) time(NULL));
      random_str = g_strdup_printf ("%d_%s", g_random_int (), timestamp);
      nonce = g_compute_checksum_for_string (G_CHECKSUM_MD5, random_str, -1);
      g_free (random_str);

      g_hash_table_insert (table, g_strdup ("oauth_timestamp"), timestamp);
      g_hash_table_insert (table, g_strdup ("oauth_nonce"), nonce);
      g_hash_table_insert (table, g_strdup ("oauth_consumer_key"), g_strdup (CONSUMER_KEY));
      g_hash_table_insert (table, g_strdup ("oauth_signature_method"), g_strdup (OAUTH_SIGNATURE_METHOD));
      g_hash_table_insert (table, g_strdup ("oauth_version"), g_strdup (OAUTH_VERSION));
    }

  /* Get the API signature from it */
  api_sig = _get_api_signature_from_hash_table (url, table, signing_key, old_auth_api);

  /* Get the signed URL with the needed params */
  if ((table != NULL) && (api_sig != NULL))
    signed_query = _get_signed_query_with_params (api_sig, table, old_auth_api);

  g_hash_table_unref (table);
  g_free (api_sig);

  va_end (args);

  retval = g_strdup_printf ("%s?%s", url, signed_query);
  g_free (signed_query);

  return retval;
}

int
main (int argc, char **argv)
{
  char line[200];
  gchar *signing_key = NULL;
  gchar *signed_url = NULL;
  gchar *token = NULL;
  gchar *token_secret = NULL;
  gchar *verifier = NULL;

  g_type_init ();

  /* Request the provisional token */
  signing_key = g_strdup_printf ("%s&", CONSUMER_SECRET);
  signed_url = _get_signed_url (FLICKR_REQUEST_TOKEN_OAUTH_URL, signing_key, FALSE,
                                "oauth_callback", OAUTH_CALLBACK_URL,
                                NULL);

  g_print ("Open the following URL in the browser to request token:\n%s\n", signed_url);
  g_free (signed_url);
  g_free (signing_key);

  /* Get data from response: request's token and request's token_secret */
  g_print ("\nEnter the request token:"); gets(line);
  token = _encode_uri (line);

  g_print ("\nEnter the request token SECRET:"); gets(line);
  token_secret = _encode_uri (line);

  /* Let the user authorize the application and grab the verification code */
  g_print ("\nOpen the following URL in the browser to authorize:\nhttp://www.flickr.com/services/oauth/authorize?perms=write&oauth_token=%s\n", token);

  g_print ("\nEnter the verification code:"); gets(line);
  verifier = _encode_uri (line);

  /* Exchange the request token for an access token */
  signing_key = g_strdup_printf ("%s&%s", CONSUMER_SECRET, token_secret);
  signed_url = _get_signed_url (FLICKR_ACCESS_TOKEN_OAUTH_URL, signing_key, FALSE,
                                "oauth_token", token,
                                "oauth_verifier", verifier,
                                NULL);

  g_print ("\nOpen the following URL in the browser to request the access token: \n%s\n", signed_url);
  g_free (signed_url);
  g_free (signing_key);

  /* Get data from response: ACCESS's token and ACCESS's token_secret */
  g_print ("\nEnter the access token:"); gets(line);
  token = _encode_uri (line);

  g_print ("\nEnter the access token SECRET:"); gets(line);
  token_secret = _encode_uri (line);

  /* Check the access token */
  signing_key = g_strdup_printf ("%s&%s", CONSUMER_SECRET, token_secret);
  signed_url = _get_signed_url (FLICKR_API_BASE_URL, signing_key, FALSE,
                                "oauth_token", token,
                                "method", "flickr.test.login",
                                NULL);

  g_print ("\nOpen the following URL in the browser to test login: \n%s\n", signed_url);
  g_free (signed_url);

  /* Get the list of groups */
  signed_url = _get_signed_url (FLICKR_API_BASE_URL, signing_key, FALSE,
                                "oauth_token", token,
                                "method", "flickr.groups.pools.getGroups",
                                NULL);

  g_print ("\nOpen the following URL in the browser to retrieve the list of groups: \n%s\n", signed_url);
  g_free (signed_url);

  g_free (signing_key);

  return 0;
}
