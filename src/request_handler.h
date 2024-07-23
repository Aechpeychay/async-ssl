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
#include <Poco/Net/MailMessage.h>
#include <Poco/Net/MailRecipient.h>
#include <Poco/Net/SMTPClientSession.h>
#include <Poco/JWT/Token.h>
#include <Poco/JWT/Signer.h>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
using namespace boost::posix_time;
using namespace std::literals;

 
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
	boost::mysql::unix_connection& conn_,
    Poco::JWT::Signer& signer)
{ 

    auto const token_ver = 
    [&req, &signer, &conn_](){
        std::string jwt = req.target().substr(7);
        Poco::JWT::Token token = signer.verify(jwt);
        std::string id = token.payload().get("id");
        if(signer.tryVerify(jwt, token)){   
            boost::mysql::statement stmt = conn_.prepare_statement(
                "update user_account set user_status = 2 where user_id = ? ;"
            ); 
            boost::mysql::results result;
            conn_.execute(stmt.bind(id), result);
        }
        http::response<http::string_body> res{http::status::unknown, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(req.keep_alive());
        res.body() = "{ \"message\" : \"log_in true\" }";
        res.prepare_payload();
        return res;
    };
   // TODO use bind in statement 
    auto const log_in = 
    [&req, &conn_](){ 
        boost::json::object log_data = boost::json::parse(req.body()).as_object();
        boost::mysql::statement stmt = conn_.prepare_statement(
            "select * from user_account where email = " + boost::json::serialize(log_data["email"]) + " and hashed_password = " + boost::json::serialize(log_data["password"]) + ";"
        );
        boost::mysql::results result;
        conn_.execute(stmt.bind(), result);
        if(result.rows().empty()){
            http::response<http::string_body> res{http::status::unknown, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(req.keep_alive());
            res.body() = "{ \"message\" : \"log_in true\" }";
            res.prepare_payload();
            return res;
        }
        else {
            http::response<http::string_body> res{http::status::unknown, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(req.keep_alive());
            res.body() = "{ \"message\" : \"log_if false\" }";
            res.prepare_payload();
            return res;
        }
    };

    // TODO: hash password
    auto const registration = 
    [&req, &conn_, &signer](){
        boost::json::object log_data = boost::json::parse(req.body()).as_object();
        std::string email = boost::json::serialize(log_data["email"]);
		boost::mysql::statement stmt = conn_.prepare_statement(
			"insert into user_account (username, hashed_password, email, created, last_activity, is_moderator, user_status)" 
            "values (?, ?, ?, NOW(), NOW(), FALSE, 1);" 
		);
        Poco::JWT::Token token;
		boost::mysql::results result;
		conn_.execute(stmt.bind(boost::json::serialize(log_data["name"]),  boost::json::serialize(log_data["password"]), boost::json::serialize(log_data["email"])), result);
        boost::mysql::statement stmt_for_id = conn_.prepare_statement(
            "select * from user_account where username = ? and hashed_password = ? and email = ? and user_status = 1;"
        );
        conn_.execute(stmt_for_id.bind(boost::json::serialize(log_data["name"]),  boost::json::serialize(log_data["password"]), boost::json::serialize(log_data["email"])), result);
        token.setSubject(std::to_string(result.rows().at(0).at(0).as_int64()));

        email.pop_back();
        Poco::Net::MailMessage msg;
        msg.addRecipient(Poco::Net::MailRecipient (Poco::Net::MailRecipient::PRIMARY_RECIPIENT,
                                          email.substr(1)));
        msg.setSender("aechpeychay@aechpeychay.ru");
        msg.setSubject("Subject");
        msg.setContent("https://aechpeychay.ru/token/" + token.toString());

        Poco::Net::SMTPClientSession smtp("connect.smtp.bz", 2525);
        smtp.login(Poco::Net::SMTPClientSession::LoginMethod::AUTH_LOGIN, "aechpeychay@aechpeychay.ru", "w1nM09FqMBmZ");
        smtp.sendMessage(msg);
        smtp.close();  

        http::response<http::string_body> res{http::status::unknown, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(req.keep_alive());
        res.body() = "{ \"message\" : \"registration\" }";
        res.prepare_payload();
        return res;
    };

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
   
    if(req.target().contains("token")){
        return send(token_ver());
    }

    // Cache the size since we need it after the move
    auto const size = body.size();

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
