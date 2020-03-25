miscellaneous = {
    'Enabled_Disabled':
        {
            '1': 'Enabled',
            '0': 'Disabled',
            ' ': 'Blank'
        },
    'The Windows dialog box title for the legal banner must be configured.':
        {None: 'Blank',
         'see': '<=== Missing Warning Title'},
    'The amount of idle time required before suspending a session must be properly set.':
        {'': ''},
    'Optional Subsystems must not be permitted to operate on the system.':
        {'': ''},
    'Users must be warned in advance of their passwords expiring.':
        {'': ''},
    'Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.':
        {
            '0': ' Encryption not allowed',
            '2147483640': 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption'
        },
    'The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.':
        {
            '0': 'Send LM & NTLM responses',
            '1': 'Send LM & NTLM - use NTLMv2 session security if negotiated',
            '2': 'Send NTLM response only',
            '3': 'Send NTLMv2 response only',
            '4': 'Send NTLMv2 response only/refuse LM',
            '5': 'Send NTLMv2 response only/refuse LM & NTLM'
        },
    'The required legal notice must be configured to display before console logon.':
        {
            None: 'Blank',
            'see': '<=== Missing Warning Message'
        },
    'The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.':
        {
            'default values after removing mrxsmb10 include the following, which are not a finding':
                'Bowser, MRxSmb20, MRxSmb30, NSI'
        },
    'Unauthorized remotely accessible registry paths must not be configured.':
        {'see': '<=== Check configured paths'},
    'Unauthorized remotely accessible registry paths and sub-paths must not be configured.':
        {'see': '<=== Check configured paths'},
    'The Security event log size must be configured to 196608 KB or greater.':
        {'': ''},
    'Caching of logon credentials must be limited.':
        {'': ''},
    'Ejection of removable NTFS media is not restricted to Administrators.':
        {
            '0': 'Administrators',
        },
    'The Smart Card removal option must be configured to Force Logoff or Lock Workstation.':
        {
            '0': 'No Action',
            '1': 'Lock Workstation',
            '2': 'Force Logoff',
            '3': 'Disconnect if a Remote Desktop Services session'
        },
    'The service principal name (SPN) target name validation level must be turned off.':
        {
            '0': 'Off',
            '1': 'Accept if provided by client',
            '2': 'Required from client'
        },
    'The system must be configured to use the Classic security model.':
        {
            '0': 'Classic - local users authenticate as themselves',
            '1': 'Guest only - local users authenticate as Guests'
        },
    'The use of DES encryption suites must not be allowed for Kerberos encryption.':
        {
            '0': 'Encryption type not allowed',
            '2147483647': 'All Options Selected'
        },
    'The system must be configured to meet the minimum session security requirement for NTLM SSP-based clients.':
        {
            '0': 'No Requirements',
            '537395200': 'Require NTLMv2 session security & Require 128-bit encryption',
            '536870912': 'Require 128-bit encryption'
        },
    'The system must be configured to meet the minimum session security requirement for NTLM SSP-based servers.':
        {
            '0': 'No Requirements',
            '537395200': 'Require NTLMv2 session security & Require 128-bit encryption',
            '536870912': 'Require 128-bit encryption'
        },
    'Users must be required to enter a password to access private keys stored on the computer.':
        {
            '0': 'User input is not required when new keys are stored and used',
            '1': 'User is prompted when the key is first used',
            '2': 'User must enter a password each time they use a key',
        },
    'User Account Control must, at minimum, prompt administrators for consent.':
        {
            '0': 'Elevate without prompting',
            '1': 'Prompt for credentials on the secure desktop',
            '2': 'Prompt for consent on the secure desktop',
            '3': 'Prompt for credentials',
            '4': 'Prompt for consent',
            '5': 'Prompt for consent for non-Windows binaries'
        },
    'User Account Control must automatically deny standard user requests for elevation.':
        {
            '0': 'Automatically deny elevation requests',
            '1': 'Prompt for credentials',
            '3': 'Prompt for credentials on the secure desktop'
        },
    'Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only '
    'Good and Unknown.':
        {
            '3': 'Good, unknown and bad but critical',
        }

}
