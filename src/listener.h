#pragma once
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <memory>
#include <string>
#include "session.h"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace mysql = boost::mysql;
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>


// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener>
{
    net::io_context& ioc_;
    ssl::context& ctx_;
    tcp::acceptor acceptor_;
    std::shared_ptr<std::string const> doc_root_;
	mysql::unix_connection& conn_;

public:
    listener(
		mysql::unix_connection& conn,
        net::io_context& ioc,
        ssl::context& ctx,
        tcp::endpoint endpoint,
        std::shared_ptr<std::string const> const& doc_root);
    // Start accepting incoming connections
    void
    run();

private:
    void
    do_accept(); 

    void
    on_accept(beast::error_code ec, tcp::socket socket);
};
