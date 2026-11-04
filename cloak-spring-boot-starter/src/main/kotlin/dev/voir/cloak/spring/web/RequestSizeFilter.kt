package dev.voir.cloak.spring.web

import dev.voir.cloak.server.error.CloakErrorCode
import jakarta.servlet.FilterChain
import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.MediaType
import org.springframework.web.filter.OncePerRequestFilter
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader

/**
 * Refuses a Cloak request whose body is larger than the server's limit with `413
 * payload_too_large`, before any of it is parsed: at once when its `Content-Length` says so, and,
 * for a body without one, as soon as reading it passes the limit.
 *
 * @property maxRequestBytes Largest body accepted, as `GET /meta` publishes it.
 */
internal class RequestSizeFilter(
    private val maxRequestBytes: Int,
) : OncePerRequestFilter() {
    /** Checks the declared size, then counts what is read. */
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        if (request.contentLengthLong > maxRequestBytes) {
            refuse(request, response)
            return
        }
        chain.doFilter(LimitedRequest(request, maxRequestBytes.toLong()), response)
    }

    /** Writes the problem itself: no handler has run, so Spring MVC's error handling is not there. */
    private fun refuse(request: HttpServletRequest, response: HttpServletResponse) {
        val code = CloakErrorCode.PAYLOAD_TOO_LARGE
        response.status = code.status
        response.contentType = MediaType.APPLICATION_PROBLEM_JSON_VALUE
        // The body is not read: tell the client the connection will not carry another request.
        response.setHeader("Connection", "close")
        CloakJsonConverter.MAPPER.writeValue(
            response.outputStream,
            Problems.of(code, RequestTooLargeException.DETAIL, request.requestURI),
        )
    }

    /**
     * A request whose body fails with [RequestTooLargeException] once more than [limit] bytes were
     * read from it.
     *
     * @property limit Largest body accepted.
     */
    private class LimitedRequest(
        request: HttpServletRequest,
        private val limit: Long,
    ) : HttpServletRequestWrapper(request) {
        /** The counting stream, made once. */
        private val stream: ServletInputStream by lazy { LimitedStream(super.getInputStream(), limit) }

        /** The body, counted. */
        override fun getInputStream(): ServletInputStream = stream

        /** The body as characters, counted as bytes. */
        override fun getReader(): BufferedReader =
            BufferedReader(InputStreamReader(stream, characterEncoding ?: Charsets.UTF_8.name()))
    }

    /**
     * Counts the bytes read through [source] and fails past [limit].
     *
     * @property source The body.
     * @property limit Largest body accepted.
     */
    private class LimitedStream(
        private val source: ServletInputStream,
        private val limit: Long,
    ) : ServletInputStream() {
        /** Bytes read so far. */
        private var count = 0L

        /** Reads one byte. */
        override fun read(): Int = source.read().also { if (it >= 0) counted(1) }

        /** Reads into a buffer. */
        override fun read(buffer: ByteArray, offset: Int, length: Int): Int =
            source.read(buffer, offset, length).also { if (it > 0) counted(it) }

        /** Whether the body is read to its end. */
        override fun isFinished(): Boolean = source.isFinished

        /** Whether reading would not block. */
        override fun isReady(): Boolean = source.isReady

        /** Passes asynchronous reading through. */
        override fun setReadListener(listener: ReadListener) = source.setReadListener(listener)

        /** Adds read bytes and fails past the limit. */
        private fun counted(bytes: Int) {
            count += bytes
            if (count > limit) throw RequestTooLargeException()
        }
    }
}

/**
 * A request body ran past the request size limit while it was read; rendered as `413
 * payload_too_large`.
 */
internal class RequestTooLargeException : IOException(DETAIL) {
    /** The problem's detail. */
    companion object {
        /** Detail of the `payload_too_large` problem for a body over the limit. */
        const val DETAIL: String = "The request body is larger than the server accepts; see maxRequestBytes in GET /meta."
    }
}
