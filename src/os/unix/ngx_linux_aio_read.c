
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


extern struct io_uring  ngx_ring;


static void ngx_file_aio_event_handler(ngx_event_t *ev);



ngx_int_t
ngx_file_aio_init(ngx_file_t *file, ngx_pool_t *pool)
{
    ngx_event_aio_t  *aio;

    aio = ngx_pcalloc(pool, sizeof(ngx_event_aio_t));
    if (aio == NULL) {
        return NGX_ERROR;
    }

    aio->file = file;
    aio->fd = file->fd;
    aio->event.data = aio;
    aio->event.ready = 1;
    aio->event.log = file->log;

    file->aio = aio;

    return NGX_OK;
}


ssize_t
ngx_file_aio_read(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
    ngx_pool_t *pool)
{
    ngx_err_t             err;
    ngx_event_t          *ev;
    ngx_event_aio_t      *aio;
    struct io_uring_sqe  *sqe;

    if (!ngx_file_aio) {
        return ngx_read_file(file, buf, size, offset);
    }

    if (file->aio == NULL && ngx_file_aio_init(file, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    aio = file->aio;
    ev = &aio->event;

    if (!ev->ready) {
        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return NGX_AGAIN;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%uz %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->active = 0;
        ev->complete = 0;

        if (aio->res >= 0) {
            ngx_set_errno(0);
            return aio->res;
        }

        ngx_set_errno(-aio->res);

        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "aio read \"%s\" failed", file->name.data);

        return NGX_ERROR;
    }

    sqe = io_uring_get_sqe(&ngx_ring);

    if (!sqe) {
        ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "aio no sqe left:%d @%O:%uz %V",
                       ev->complete, offset, size, &file->name);
        return ngx_read_file(file, buf, size, offset);
    }

    /* We must store iov into heap to prevent kernel from returning -EFAULT */
    aio->iov.iov_base = buf;
    aio->iov.iov_len = size;
    io_uring_prep_readv(sqe, file->fd, &aio->iov, 1, offset);
    io_uring_sqe_set_data(sqe, ev);


    ev->handler = ngx_file_aio_event_handler;

    if (io_uring_submit(&ngx_ring) == 1) {
        ev->active = 1;
        ev->ready = 0;
        ev->complete = 0;

        return NGX_AGAIN;
    }

    err = ngx_errno;

    if (err == NGX_EAGAIN) {
        return ngx_read_file(file, buf, size, offset);
    }

    ngx_log_error(NGX_LOG_CRIT, file->log, err,
                  "io_submit(\"%V\") failed", &file->name);

    if (err == NGX_ENOSYS) {
        ngx_file_aio = 0;
        return ngx_read_file(file, buf, size, offset);
    }

    return NGX_ERROR;
}


static void
ngx_file_aio_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t  *aio;

    aio = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    aio->handler(ev);
}
