#pragma once
#include "boost/date_time/posix_time/posix_time.hpp"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <boost/mysql/unix.hpp>
#include <boost/json.hpp>
#include <Poco/Net/SMTPClientSession.h>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
using namespace boost::posix_time;
using namespace std::literals;

 
    // Send email
//    void email_sender();
	// Return a reasonable mime type based on the extension of a file.
	beast::string_view
	mime_type(beast::string_view path);

	// Append an HTTP rel-path to a local filesystem path.
	// The returned path is normalized for the platform.
	std::string
	path_cat(
		beast::string_view base,
		beast::string_view path);
// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
	class Body, class Allocator,
	class Send>
void
handle_request(
	beast::string_view doc_root,
	http::request<Body, http::basic_fields<Allocator>>&& req,
	Send&& send,	
	boost::mysql::unix_connection& conn_)
{
      

    auto const log_in = 
    [&req, &conn_](){ 
        boost::json::object log_data = boost::json::parse(req.body()).as_object();
        boost::mysql::statement stmt = conn_.prepare_statement(
            "select * form user_account where email = '" + boost::json::serialize(log_data["email"]) + "' and password = '" + boost::json::serialize(log_data["password"]) + "';"
        );
        boost::mysql::results result;
        conn_.execute(stmt.bind(), result);
        if(result.empty()){
            http::response<http::string_body> res{http::status::unknown, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = "failed to login";
            res.prepare_payload();
            return res;
        }
        else {
            http::response<http::string_body> res{http::status::unknown, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = "successfuly login";
            res.prepare_payload();
            return res;
        }
    };

    // TODO:: hash password
    auto const registration = 
    [&req, &conn_](){
        boost::json::object log_data = boost::json::parse(req.body()).as_object();
		boost::mysql::statement stmt = conn_.prepare_statement(
			"insert into user_account (username, hashed_password, email, created, last_activity, is_moderator, user_status)" 
            "values ('" + boost::json::serialize(log_data["name"]) + "', '" + boost::json::serialize(log_data["password"]) +  "' , '" + boost::json::serialize(log_data["email"]) + "',  NOW(), NOW(), FALSE, 1);" 
		);
		boost::mysql::results result;
		conn_.execute(stmt.bind(), result);
        http::response<http::string_body> res{http::status::unknown, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "successful";
        res.prepare_payload();
        return res;
    };

    // Returns a bad request response
    auto const bad_request =
    [&req](beast::string_view why)
    {
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    };

    // Returns a not found response
    auto const not_found =
    [&req](beast::string_view target)
    {
        http::response<http::string_body> res{http::status::not_found, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "The resource '" + std::string(target) + "' was not found.";
        res.prepare_payload();
        return res;
    };

    // Returns a server error response
    auto const server_error =
    [&req](beast::string_view what)
    {
        http::response<http::string_body> res{http::status::internal_server_error, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "An error occurred: '" + std::string(what) + "'";
        res.prepare_payload();
        return res;
    };

    // Request path must be absolute and not contain "..".
    if( req.target().empty() ||
        req.target()[0] != '/' ||
        req.target().find("..") != beast::string_view::npos)
        return send(bad_request("Illegal request-target"));

    // Build the path to the requested file
    std::string path = path_cat(doc_root, req.target());
    if(req.target().back() == '/')
        path.append("index.html");

    // Attempt to open the file
    beast::error_code ec;
    http::file_body::value_type body;
    body.open(path.c_str(), beast::file_mode::scan, ec);

    // Registrate user
	if(req.target() == "/register"){
        return send(registration());
	}
    if(req.target() == "/log_in"){
        return send(log_in());   
    }
    // Handle the case where the file doesn't exist
    if(ec == beast::errc::no_such_file_or_directory)
        return send(not_found(req.target()));

    // Handle an unknown error
    if(ec)
        return send(server_error(ec.message()));

    // Cache the size since we need it after the move
    auto const size = body.size();

    // Respond to HEAD request
    if(req.method() == http::verb::head)
    {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, mime_type(path));
        res.content_length(size);
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }

    // Respond to GET request
    http::response<http::file_body> res{
        std::piecewise_construct,
        std::make_tuple(std::move(body)),
        std::make_tuple(http::status::ok, req.version())};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, mime_type(path));
    res.content_length(size);
    res.keep_alive(req.keep_alive());
    return send(std::move(res));
}
