using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;

namespace ImpersonationTesting
{
    public class Impersonate : IDisposable
    {
        private const int LOGON32_PROVIDER_DEFAULT = 0;
        private const int LOGON32_LOGON_INTERACTIVE = 2;

        private readonly string _domain;
        private readonly string _username;
        private readonly SecureString _password;
        private IntPtr _userToken;
        private bool _isDisposed;

        public Impersonate(string domain, string username, SecureString password)
        {
            _domain = domain;
            _username = username;
            _password = password;
        }

        [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
        public void RunAsImpersonatedUser(Action action)
        {
            _userToken = IntPtr.Zero;

            bool logonSuccessfull = LogonUser(_username, _domain, _password.ToPlainString(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ref _userToken);

            if (logonSuccessfull == false)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error);
            }

            using (var impersonationIdentity = new WindowsIdentity(_userToken))
            using (WindowsImpersonationContext context = impersonationIdentity.Impersonate())
            {
                action();
            }
        }

        public void Dispose()
        {
            DisposeOfUserToken();
        }

        private void DisposeOfUserToken()
        {
            if (_isDisposed)
            {
                return;
            }

            _isDisposed = true;

            CloseHandle(_userToken);
        }

        ~Impersonate()
        {
            DisposeOfUserToken();
        }

        #region P/Invoke Methods

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern bool CloseHandle(IntPtr handle);

        #endregion
    }
}
