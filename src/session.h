#pragma once 
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <boost/mysql.hpp>
#include "request_handler.h"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace mysql = boost::mysql;
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>


// Report a failure
void
fail(beast::error_code ec, char const* what);

// Handles an HTTP server connection
class session : public std::enable_shared_from_this<session>
{
    // This is the C++11 equivalent of a generic lambda.
    // The function object is used to send an HTTP message.
    struct send_lambda
    {
        session& self_;

        explicit
        send_lambda(session& self);

        template<bool isRequest, class Body, class Fields>
        void
        operator()(http::message<isRequest, Body, Fields>&& msg) const;
    };

    beast::ssl_stream<beast::tcp_stream> stream_;
    beast::flat_buffer buffer_;
    std::shared_ptr<std::string const> doc_root_;
    http::request<http::string_body> req_;
    std::shared_ptr<void> res_;
    send_lambda lambda_;
	mysql::unix_connection& conn_;
	
public:
    // Take ownership of the socket
    explicit
    session(
		mysql::unix_connection& conn,
        tcp::socket&& socket,
        ssl::context& ctx,
        std::shared_ptr<std::string const> const& doc_root);

    // Start the asynchronous operation
    void
    run();

    void
    on_handshake(beast::error_code ec);

    void
    do_read();

    void
    on_read(
        beast::error_code ec,
        std::size_t bytes_transferred);

    void
    on_write(
        bool close,
        beast::error_code ec,
        std::size_t bytes_transferred);

    void
    do_close();

    void
    on_shutdown(beast::error_code ec);
};

