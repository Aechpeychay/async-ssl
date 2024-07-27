//
// Copyright (c) 2018 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/vinniefalco/CppCon2018
//

//------------------------------------------------------------------------------
/*
    WebSocket chat server

    This implements a multi-user chat room using WebSocket.
*/
//------------------------------------------------------------------------------
#include <boost/mysql/error_with_diagnostics.hpp>
#include <boost/mysql/handshake_params.hpp>
#include <boost/mysql/results.hpp>
#include <boost/mysql/tcp_ssl.hpp>
#include <boost/mysql/unix.hpp>
#define BOOST_ASIO_HAS_LOCAL_SOCKETS
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/system/system_error.hpp>
#include <iostream>
#include <string>
#include <boost/asio/signal_set.hpp>
#include <iostream>
#include <thread>

#include "listener.h"
#include "server_certificate.h"

using boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;
namespace mysql = boost::mysql;
typedef ssl::stream<tcp::socket> ssl_socket;

namespace {

// Запускает функцию fn на n потоках, включая текущий
template <typename Fn>
void RunWorkers(unsigned n, const Fn& fn) {
    n = std::max(1u, n);
    std::vector<std::jthread> workers;
    workers.reserve(n - 1);
    // Запускаем n-1 рабочих потоков, выполняющих функцию fn
    while (--n) {
        workers.emplace_back(fn);
    }
    fn();
}

}  // namespace

int
main(int argc, char* argv[])
{
    // Check command line arguments.
    if (argc != 4)
    {
        std::cerr <<
            "Usage: http-server-async-ssl <address> <port> <doc_root> \n" <<
            "Example:\n" <<
            "    http-server-async-ssl 0.0.0.0 8080 .\n";
        return EXIT_FAILURE;
    }
    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const doc_root = std::make_shared<std::string>(argv[3]);

    const unsigned num_threads = std::thread::hardware_concurrency();

    // The io_context is required for all I/O
    net::io_context ioc{num_threads};

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tlsv12};

    // This holds the self-signed certificate used by the server
    load_server_certificate(ctx);

    const char* socket_path = "/var/run/mysqld/mysqld.sock";

	// Represents a connection to the MySQL server.
	mysql::unix_connection conn(ioc);

	// Resolve the hostname to get a collection of endpoints
	boost::asio::ip::tcp::resolver resolver(ioc.get_executor());

    boost::asio::local::stream_protocol::endpoint ep(socket_path);

	// The username, password and database to use
	mysql::handshake_params params(
		"db_forum_user",                // username
		"9789851D",                // password
		"db_forum"  // database
	);

	// Connect to the server using the first endpoint returned by the resolver
	conn.connect(ep, params);

    Poco::Redis::Client redis_conn;
    redis_conn.connect("127.0.0.0:6379");

    // Create and launch a listening port
    std::make_shared<listener>(
        redis_conn,
		conn,
        ioc,
        ctx,
        tcp::endpoint{address, port},
        doc_root)->run();

	// 6. Запускаем обработку асинхронных операций
	RunWorkers(std::max(1u, num_threads), [&ioc] {
		ioc.run();
	});


    // (If we get here, it means we got a SIGINT or SIGTERM)

    return EXIT_SUCCESS;
}
