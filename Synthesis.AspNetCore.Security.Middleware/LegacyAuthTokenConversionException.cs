using System;

namespace Synthesis.AspNetCore.Security.Middleware
{
    public class LegacyAuthTokenConversionException : Exception
    {
        public LegacyAuthTokenConversionException()
        {
        }

        public LegacyAuthTokenConversionException(string message)
            : base(message)
        {
        }

        public LegacyAuthTokenConversionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        public string ReasonPhrase { get; set; }
    }
}
