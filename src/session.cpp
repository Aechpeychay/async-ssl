#include "session.h"
	void
	fail(beast::error_code ec, char const* what)
	{
		// ssl::error::stream_truncated, also known as an SSL "short read",
		// indicates the peer closed the connection without performing the
		// required closing handshake (for example, Google does this to
		// improve performance). Generally this can be a security issue,
		// but if your communication protocol is self-terminated (as
		// it is with both HTTP and WebSocket) then you may simply
		// ignore the lack of close_notify.
		//
		// https://github.com/boostorg/beast/issues/38
		//
		// https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
		//
		// When a short read would cut off the end of an HTTP message,
		// Beast returns the error beast::http::error::partial_message.
		// Therefore, if we see a short read here, it has occurred
		// after the message has been completed, so it is safe to ignore it.

		if(ec == net::ssl::error::stream_truncated)
			return;

		std::cerr << what << ": " << ec.message() << "\n";
	}

	session::send_lambda::send_lambda(session& self)
		: self_(self)
	{
	}
	template<bool isRequest, class Body, class Fields>
	void
	session::send_lambda::operator()(http::message<isRequest, Body, Fields>&& msg) const
	{
		// The lifetime of the message has to extend
		// for the duration of the async operation so
		// we use a shared_ptr to manage it.
		auto sp = std::make_shared<
			http::message<isRequest, Body, Fields>>(std::move(msg));

		// Store a type-erased version of the shared
		// pointer in the class to keep it alive.
		self_.res_ = sp;

		// Write the response
		http::async_write(
			self_.stream_,
			*sp,
			beast::bind_front_handler(
				&session::on_write,
				self_.shared_from_this(),
				sp->need_eof()));
	}
    session::session(
        Poco::Redis::Client& redis_conn,
		mysql::unix_connection& conn,
        tcp::socket&& socket,
        ssl::context& ctx,
        std::shared_ptr<std::string const> const& doc_root,
        std::string signer)
		: conn_(conn)
        , stream_(std::move(socket), ctx)
        , doc_root_(doc_root)
        , lambda_(*this)
        , signer(signer)
    {
    }
	void
    session::run()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Perform the SSL handshake
        stream_.async_handshake(
            ssl::stream_base::server,
            beast::bind_front_handler(
                &session::on_handshake,
                shared_from_this()));
    }

    void
    session::on_handshake(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "handshake");

        do_read();
    }

    void
    session::do_read()
    {
        // Make the request empty before reading,
        // otherwise the operation behavior is undefined.
        req_ = {};

        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Read a request
        http::async_read(stream_, buffer_, req_,
            beast::bind_front_handler(
                &session::on_read,
                shared_from_this()));
    }

	void
    session::on_read(
    beast::error_code ec,
    std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return do_close();

        if(ec)
            return fail(ec, "read");

        // Send the response
        handle_request(*doc_root_, std::move(req_), lambda_, conn_, signer, redis_conn_);
    }

	void
    session::on_write(
    bool close,
    beast::error_code ec,
    std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        if(close)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return do_close();
        }

        // We're done with the response so delete it
        res_ = nullptr;

        // Read another request
        do_read();
    }

	void
    session::do_close()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Perform the SSL shutdown
        stream_.async_shutdown(
            beast::bind_front_handler(
                &session::on_shutdown,
                shared_from_this()));
    }

	void
    session::on_shutdown(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "shutdown");

        // At this point the connection is closed gracefully
    }
	
