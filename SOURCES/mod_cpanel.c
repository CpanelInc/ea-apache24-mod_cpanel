#include "dirent.h"
#include <pwd.h>
#include <unistd.h>

#include "httpd.h"
#include "http_core.h"
#include "http_request.h"

#include "http_log.h"

#include "apr_tables.h"
#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#define MODULE_NAME "mod_cpanel"
#define MODULE_VERSION "1.0"

/* The debug setting will log the full cache behavior */
#ifdef CPANEL_DEBUG
#define DEBUG_printf(fmt, ...) \
    do { ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, ("mod_cpanel %s(): " fmt),  __FUNCTION__, ##__VA_ARGS__); } while (0)
#else
#define DEBUG_printf(fmt, ...)
#endif

module AP_MODULE_DECLARE_DATA cpanel_module;

typedef struct
{
    /*apr_finfo_t finfo;*/
    ap_configfile_t **conffile;
    apr_status_t status;
} htaccess_cache_entry;

typedef struct
{
    int populated_suspended_users;
    apr_hash_t *htaccess_cache_table;
    apr_array_header_t *suspended_users;
} cpanel_server_config;

/*
 * Populates the suspended_users array in the server_config struct
 * once upon startup.
 *
 * It checks the /var/cpanel/suspended/ directory for user name entries
 * and populates the array with their homedirs. Any request going to a
 * matching homedir is redirected to the suspended page.
 *
 * Because this does *not* happen more than once - this code doesn't worry
 * about thread-safety - as we only read from this populated array in the
 * access check calls.
 */
static void *populate_suspended_users(cpanel_server_config *sconf, apr_pool_t *pool)
{
    struct dirent *de;
    DIR *dr = opendir("/var/cpanel/suspended/");

    if (dr == NULL)  // opendir returns NULL if couldn't open directory
    {
        ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, pool, "Failed to populate suspended users. Could not open directory: %s", "/var/cpanel/suspended");
        sconf->populated_suspended_users = 0;
        return NULL;
    }

    sconf->suspended_users = apr_array_make(pool, 16, sizeof(const char*));
    while ((de = readdir(dr)) != NULL) {
        if (!(strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)) {
            struct passwd *pw;
            if ((pw = getpwnam(de->d_name)) == NULL) {
                continue;
            }
            *(const char**)apr_array_push(sconf->suspended_users) = apr_pstrdup(pool, pw->pw_dir);
        }
    }
    closedir(dr);

    sconf->populated_suspended_users = 1;

    return NULL;
}

static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    cpanel_server_config *sconf = apr_palloc(s->process->pool, sizeof(cpanel_server_config));
    sconf->htaccess_cache_table = apr_hash_make(s->process->pool);

    /* Populate the suspended users list */
    populate_suspended_users(sconf, s->process->pool);

    return sconf;
}

static int cpanel_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *main_server)
{
    ap_add_version_component(p, MODULE_NAME "/" MODULE_VERSION);

    return OK;
}

static int suspended_user_handler(request_rec *r)
{
    cpanel_server_config *sconf;
    sconf = ap_get_module_config(r->server->module_config, &cpanel_module);

    if (!sconf->populated_suspended_users) {
        return (DECLINED);
    }

    char *filename;
    filename = apr_pstrdup(r->pool, r->filename);

    for (int i = 0; i < sconf->suspended_users->nelts; i++) {
        const char *user_homedir = ((const char**)sconf->suspended_users->elts)[i];
        if ( strncmp(user_homedir, filename, strlen(user_homedir)) == 0 ) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Request for '%s' belonging to a suspended account - redirecting to suspended page", filename);

            r->status = HTTP_MOVED_TEMPORARILY;
            r->content_type = "text/html";
            apr_table_setn(r->headers_out, "Location", "/cgi-sys/suspendedpage.cgi" );

            return HTTP_MOVED_TEMPORARILY;
        }
    }

    return (DECLINED);
}

/*
 * Cache hits to non-existent htaccess files.
 *
 * If the htaccess filepath is new (i.e, not in the cache already), then
 * perform an ap_pcfg_openfile() call on it, and check the status.
 * If the status is ENOENT or ENOTDIR, then add this to the cache table.
 *
 * Note: each 'cache' is populated within the process pools and not shared
 * amount the child processes - therefore, on MPMs which fork, each child process
 * will need some 'priming' to happen before it starts returning hits from the cache.
 *
 * Because we are using a hashtable as the data structure underneath, we are not
 * doing a mutex locks on threaded MPMs as the worst that can happen is the hash entry
 * is collabered.
 */
static apr_status_t cpanel_open_htaccess(request_rec *r, const char *dir_name, const char *access_name, ap_configfile_t **conffile, const char **full_name)
{
    cpanel_server_config *sconf;
    sconf = ap_get_module_config(r->server->module_config, &cpanel_module);

    *full_name = ap_make_full_path(r->server->process->pool, dir_name, access_name);
    apr_size_t name_len = strlen(*full_name);

    htaccess_cache_entry *cached_entry = apr_hash_get(sconf->htaccess_cache_table, (void *)*full_name, name_len);
    if ( cached_entry != NULL ) {
        DEBUG_printf("Cache-hit: htaccess request for '%s'", *full_name);
        /*
         * TODO: cache finfo, or stat files periodically to avoid requiring
         * a restart to get *new* .htaccess files automatically to take effect.
         * cached_entry->status = apr_stat(&cached_entry->finfo, *full_name, APR_FINFO_IDENT | APR_FINFO_MIN | APR_FINFO_PROT, cache_pool);
         */
        conffile = (ap_configfile_t **)&cached_entry->conffile;
        return cached_entry->status;
    }

    DEBUG_printf("Cache-miss: htaccess request for '%s'", *full_name);

    cached_entry = apr_palloc(r->server->process->pool, (sizeof(htaccess_cache_entry) + name_len + 1));
    cached_entry->status = ap_pcfg_openfile(conffile, r->server->process->pool, *full_name);
    cached_entry->conffile = conffile;

    /*
     * Cache the 'negative' htaccess hit. Basically, if the file did not exist, or we couldn't
     * read it, then cache the state so we dont have to try that file again.
     */
    if ( APR_STATUS_IS_ENOENT(cached_entry->status) || APR_STATUS_IS_ENOTDIR(cached_entry->status) ) {
        DEBUG_printf("Caching htaccess request for '%s'", *full_name);
        apr_hash_set(sconf->htaccess_cache_table, (void *)*full_name, name_len, (void *)cached_entry);
    }

    return cached_entry->status;
}

/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool)
{
    /* Set the module version */
    ap_hook_post_config(cpanel_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    static const char * const suspend_post[] = { "mod_alias.c", "mod_redirect.c", NULL };
    ap_hook_check_access(suspended_user_handler, NULL, suspend_post, APR_HOOK_REALLY_FIRST, AP_AUTH_INTERNAL_PER_CONF);

    /*
     * Since itk can simply exit the process in its hook, run it first.
     * This way, we do not have to do any unnecessary work.
     */
    static const char * const open_htaccess_pre[] = { "mpm_itk.c", NULL };
    ap_hook_open_htaccess(cpanel_open_htaccess, open_htaccess_pre, NULL, APR_HOOK_REALLY_FIRST);

    return;
}

AP_DECLARE_MODULE(cpanel) = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_server_config, /* Populate the server_config struct */
    NULL,
    NULL, /*
           * TODO: Add directives to control the behavior. Something like the following:
           *  HtaccessCachingStrategy "negative"
           *  HtaccessCacheTimeOut 5
          */
    register_hooks      /* Our hook registering function */
};

