namespace Synthesis.AspNetCore.Security.Middleware.Identity
{
    internal enum AuthenticateUserResponseResultCode
    {
        Success,
        TooManyLoginAttempts,
        InvalidLogin,
        UserIsLocked,
        PasswordExpired,
        PasswordWillExpire,
        InvalidActiveDirectoryAccount,
        InvalidActiveDirectoryUser,
        ActiveDirectoryNotConfiguredForAccount,
        InvalidClientCertificate,
        ClientCertificateExpired,
        LicenseCheckFailed,
        EmailIsNotVerified,
        EmailVerificationFailed,
        IdpUserLoggingInAsLocalUser,
        LocalUserLoggingInAsIdpUser,
        AutoProvisionDisabled,
        InvalidUserGroup,
        GuestUserLoggingInAsAdminUser
    }
}
