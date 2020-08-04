using System;
using System.Net;

namespace WebMvc.Extensions
{
    public class CustomHttpRequestException : Exception
    {
        public readonly HttpStatusCode StatusCode;

        public CustomHttpRequestException() { }

        public CustomHttpRequestException(string message, Exception innerException)
            : base(message, innerException) { }

        public CustomHttpRequestException(HttpStatusCode statusCode)
        {
            StatusCode = statusCode;
        }
    }
}