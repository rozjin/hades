#ifndef PROTOCOL_BLOCKDEV_HPP
#define PROTOCOL_BLOCKDEV_HPP

#include <frg/functional.hpp>
#include <ipc/message.hpp>
#include <ipc/port.hpp>
#include <util/types.hpp>

namespace ipc {
    namespace protocols {
        template<typename T>
        struct blockdev {
            ipc::port<T> *port;
            T *owner;
            struct _on_open {
                static constexpr size_t id = 57342811;
                blockdev *interf;
                frg::bound_mem_fn<&T::handleOn_Open> handler;
                private:
                    struct [[gnu::packed]] send_arguments {
                        void *fd;
                        ssize_t flags;
                        send_arguments(void *fd,ssize_t flags): fd(fd),flags(flags) {}
                    };
                public:
                    template<typename... Args>
                    ssize_t operator()(Args &&... args) {
                        send_arguments send_args{std::forward<Args>(args)...};
                    
                        ipc::header header{id, sizeof(send_arguments), &send_args};
                        size_t id = interf->port->getTxnTx()->send(&header);
                    
                        return *(ssize_t  *) interf->port->getRcvRx()->recv(id)->data;
                    }
                    
                    void onRx(size_t id, void *payload, size_t len) {
                        if (len < sizeof(send_arguments)) {
                            ipc::header header{empty::id, sizeof(empty), nullptr};
                            interf->port->getRcvTx()->send(&header, id);
                        }
                    
                        send_arguments *send_args = (send_arguments *) payload;
                        canceller<blockdev> do_cancel{interf, id};
                        ssize_t  res = handler(do_cancel,send_args->fd,send_args->flags);
                        protocols::reply<ssize_t > reply{res};
                        ipc::header header{protocols::reply<ssize_t >::id, sizeof(protocols::reply<ssize_t >), &reply};
                        interf->port->getRcvTx()->send(&header, id);
                    }
                    _on_open(blockdev *interf): interf(interf), handler(interf->owner) {}
            };
            struct _on_close {
                static constexpr size_t id = 2423284139;
                blockdev *interf;
                frg::bound_mem_fn<&T::handleOn_Close> handler;
                private:
                    struct [[gnu::packed]] send_arguments {
                        void *fd;
                        ssize_t flags;
                        send_arguments(void *fd,ssize_t flags): fd(fd),flags(flags) {}
                    };
                public:
                    template<typename... Args>
                    ssize_t operator()(Args &&... args) {
                        send_arguments send_args{std::forward<Args>(args)...};
                    
                        ipc::header header{id, sizeof(send_arguments), &send_args};
                        size_t id = interf->port->getTxnTx()->send(&header);
                    
                        return *(ssize_t  *) interf->port->getRcvRx()->recv(id)->data;
                    }
                    
                    void onRx(size_t id, void *payload, size_t len) {
                        if (len < sizeof(send_arguments)) {
                            ipc::header header{empty::id, sizeof(empty), nullptr};
                            interf->port->getRcvTx()->send(&header, id);
                        }
                    
                        send_arguments *send_args = (send_arguments *) payload;
                        canceller<blockdev> do_cancel{interf, id};
                        ssize_t  res = handler(do_cancel,send_args->fd,send_args->flags);
                        protocols::reply<ssize_t > reply{res};
                        ipc::header header{protocols::reply<ssize_t >::id, sizeof(protocols::reply<ssize_t >), &reply};
                        interf->port->getRcvTx()->send(&header, id);
                    }
                    _on_close(blockdev *interf): interf(interf), handler(interf->owner) {}
            };
            struct _read {
                static constexpr size_t id = 3194463658;
                blockdev *interf;
                frg::bound_mem_fn<&T::handleRead> handler;
                private:
                    struct [[gnu::packed]] send_arguments {
                        void *buf;
                        size_t len;
                        size_t offset;
                        send_arguments(void *buf,size_t len,size_t offset): buf(buf),len(len),offset(offset) {}
                    };
                public:
                    template<typename... Args>
                    ssize_t operator()(Args &&... args) {
                        send_arguments send_args{std::forward<Args>(args)...};
                    
                        ipc::header header{id, sizeof(send_arguments), &send_args};
                        size_t id = interf->port->getTxnTx()->send(&header);
                    
                        return *(ssize_t  *) interf->port->getRcvRx()->recv(id)->data;
                    }
                    
                    void onRx(size_t id, void *payload, size_t len) {
                        if (len < sizeof(send_arguments)) {
                            ipc::header header{empty::id, sizeof(empty), nullptr};
                            interf->port->getRcvTx()->send(&header, id);
                        }
                    
                        send_arguments *send_args = (send_arguments *) payload;
                        canceller<blockdev> do_cancel{interf, id};
                        ssize_t  res = handler(do_cancel,send_args->buf,send_args->len,send_args->offset);
                        protocols::reply<ssize_t > reply{res};
                        ipc::header header{protocols::reply<ssize_t >::id, sizeof(protocols::reply<ssize_t >), &reply};
                        interf->port->getRcvTx()->send(&header, id);
                    }
                    _read(blockdev *interf): interf(interf), handler(interf->owner) {}
            };
            struct _write {
                static constexpr size_t id = 2881317064;
                blockdev *interf;
                frg::bound_mem_fn<&T::handleWrite> handler;
                private:
                    struct [[gnu::packed]] send_arguments {
                        void *buf;
                        size_t len;
                        size_t offset;
                        send_arguments(void *buf,size_t len,size_t offset): buf(buf),len(len),offset(offset) {}
                    };
                public:
                    template<typename... Args>
                    ssize_t operator()(Args &&... args) {
                        send_arguments send_args{std::forward<Args>(args)...};
                    
                        ipc::header header{id, sizeof(send_arguments), &send_args};
                        size_t id = interf->port->getTxnTx()->send(&header);
                    
                        return *(ssize_t  *) interf->port->getRcvRx()->recv(id)->data;
                    }
                    
                    void onRx(size_t id, void *payload, size_t len) {
                        if (len < sizeof(send_arguments)) {
                            ipc::header header{empty::id, sizeof(empty), nullptr};
                            interf->port->getRcvTx()->send(&header, id);
                        }
                    
                        send_arguments *send_args = (send_arguments *) payload;
                        canceller<blockdev> do_cancel{interf, id};
                        ssize_t  res = handler(do_cancel,send_args->buf,send_args->len,send_args->offset);
                        protocols::reply<ssize_t > reply{res};
                        ipc::header header{protocols::reply<ssize_t >::id, sizeof(protocols::reply<ssize_t >), &reply};
                        interf->port->getRcvTx()->send(&header, id);
                    }
                    _write(blockdev *interf): interf(interf), handler(interf->owner) {}
            };
            struct _ioctl {
                static constexpr size_t id = 1187409964;
                blockdev *interf;
                frg::bound_mem_fn<&T::handleIoctl> handler;
                private:
                    struct [[gnu::packed]] send_arguments {
                        size_t req;
                        void *buf;
                        send_arguments(size_t req,void *buf): req(req),buf(buf) {}
                    };
                public:
                    template<typename... Args>
                    ssize_t operator()(Args &&... args) {
                        send_arguments send_args{std::forward<Args>(args)...};
                    
                        ipc::header header{id, sizeof(send_arguments), &send_args};
                        size_t id = interf->port->getTxnTx()->send(&header);
                    
                        return *(ssize_t  *) interf->port->getRcvRx()->recv(id)->data;
                    }
                    
                    void onRx(size_t id, void *payload, size_t len) {
                        if (len < sizeof(send_arguments)) {
                            ipc::header header{empty::id, sizeof(empty), nullptr};
                            interf->port->getRcvTx()->send(&header, id);
                        }
                    
                        send_arguments *send_args = (send_arguments *) payload;
                        canceller<blockdev> do_cancel{interf, id};
                        ssize_t  res = handler(do_cancel,send_args->req,send_args->buf);
                        protocols::reply<ssize_t > reply{res};
                        ipc::header header{protocols::reply<ssize_t >::id, sizeof(protocols::reply<ssize_t >), &reply};
                        interf->port->getRcvTx()->send(&header, id);
                    }
                    _ioctl(blockdev *interf): interf(interf), handler(interf->owner) {}
            };
            struct _poll {
                static constexpr size_t id = 3527766994;
                blockdev *interf;
                frg::bound_mem_fn<&T::handlePoll> handler;
                private:
                    struct [[gnu::packed]] send_arguments {
                        void *thread;
                        send_arguments(void *thread): thread(thread) {}
                    };
                public:
                    template<typename... Args>
                    ssize_t operator()(Args &&... args) {
                        send_arguments send_args{std::forward<Args>(args)...};
                    
                        ipc::header header{id, sizeof(send_arguments), &send_args};
                        size_t id = interf->port->getTxnTx()->send(&header);
                    
                        return *(ssize_t  *) interf->port->getRcvRx()->recv(id)->data;
                    }
                    
                    void onRx(size_t id, void *payload, size_t len) {
                        if (len < sizeof(send_arguments)) {
                            ipc::header header{empty::id, sizeof(empty), nullptr};
                            interf->port->getRcvTx()->send(&header, id);
                        }
                    
                        send_arguments *send_args = (send_arguments *) payload;
                        canceller<blockdev> do_cancel{interf, id};
                        ssize_t  res = handler(do_cancel,send_args->thread);
                        protocols::reply<ssize_t > reply{res};
                        ipc::header header{protocols::reply<ssize_t >::id, sizeof(protocols::reply<ssize_t >), &reply};
                        interf->port->getRcvTx()->send(&header, id);
                    }
                    _poll(blockdev *interf): interf(interf), handler(interf->owner) {}
            };
            _on_open on_open{this};
            _on_close on_close{this};
            _read read{this};
            _write write{this};
            _ioctl ioctl{this};
            _poll poll{this};
            blockdev(T *owner, ipc::port<T> *port): owner(owner), port(port) {}
        };
    
    }
}

#endif