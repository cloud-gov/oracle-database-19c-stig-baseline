control 'SV-270587' do
  title 'Oracle Database must, for password-based authentication, verify that when users create or update passwords, the passwords are not found on the list of commonly used, expected, or compromised passwords in IA-5 (1) (a).'
  desc 'Password-based authentication applies to passwords regardless of whether they are used in single-factor or multifactor authentication (MFA). Long passwords or passphrases are preferable over shorter passwords. Enforced composition rules provide marginal security benefits while decreasing usability. However, organizations may choose to establish certain rules for password generation (e.g., minimum character length for long passwords) under certain circumstances and can enforce this requirement in IA-5(1)(h). Account recovery can occur, for example, in situations when a password is forgotten. Cryptographically protected passwords include salted one-way cryptographic hashes of passwords. The list of commonly used, compromised, or expected passwords includes passwords obtained from previous breach corpuses, dictionary words, and repetitive or sequential characters. The list includes context-specific words, such as the name of the service, username, and derivatives thereof.'
  desc 'check', "Verify the database management system (DBMS) is configured to verify when users create or update passwords, that the passwords are not found on the list of commonly used, expected, or compromised passwords in IA-5 (1) (a).

If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

For each profile that can be applied to accounts where authentication is under Oracle's control, determine the password verification function that is in use:

SELECT * FROM SYS.DBA_PROFILES 
WHERE RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
ORDER BY PROFILE;

Note: Profiles can inherit settings from another profile so some password functions could be set to DEFAULT. If so, review the DEFAULT profile function name. 

If the function name is null for any profile, this is a finding.

Review the password verification functions specified for the PASSWORD_VERIFY_FUNCTION settings for each profile. Determine whether it is configured for when users create or update passwords, that the passwords are not found on the list of commonly-used, expected, or compromised passwords.
 
If the verify_function is not configured to verify when users create or update passwords, that the passwords are not found on the list of commonly-used, expected, or compromised passwords in IA-5 (1) (a), this is a finding."
  desc 'fix', 'If any user accounts are managed by Oracle, develop, test, and implement a password verification function that enforces DOD requirements.

Configure the password verify function to verify when users create or update passwords, that the passwords are not found on the list of commonly-used, expected, or compromised passwords in IA-5 (1) (a).

Oracle supplies a sample function called ORA12C_STIG_VERIFY_FUNCTION. This can be used as the starting point for a customized function. The script file is found in the following location on the server depending on OS:

Windows:
%ORACLE_HOME%\\RDBMS\\ADMIN\\catpvf.sql

Unix/Linux:
$ORACLE_HOME/rdbms/admin/catpvf.sql'
  impact 0.5
  tag check_id: 'C-74620r1065037_chk'
  tag severity: 'medium'
  tag gid: 'V-270587'
  tag rid: 'SV-270587r1112489_rule'
  tag stig_id: 'O19C-00-019800'
  tag gtitle: 'SRG-APP-000845-DB-000220'
  tag fix_id: 'F-74521r1112488_fix'
  tag 'documentable'
  tag cci: ['CCI-004061']
  tag nist: ['IA-5 (1) (b)']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), port: input('port'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))
  approved_password_verify_functions = input('approved_password_verify_functions').map { |function| function.to_s.strip.upcase }

  # Sibling of SV-270561 (IA-5(1)(a)): SV-270587 (IA-5(1)(b)) has the same
  # SQL-verifiable null check over SYS.DBA_PROFILES, plus a function-code review
  # that is not portably SQL-decidable. Require each profile's effective
  # PASSWORD_VERIFY_FUNCTION to be non-null and explicitly approved by the caller.

  # Profiles actually assigned to users (profiles-in-use convention, per
  # SV-270549/551/561). Resolve DEFAULT in one query and encode both values in one
  # column so we can use the reliable .column accessor without interpolating
  # profile names back into SQL.
  profile_functions = sql.query(%{
    SELECT DISTINCT
           u.profile || '|' || DECODE(p.limit, 'DEFAULT', dp.limit, p.limit) AS profile_function
    FROM dba_users u
    JOIN dba_profiles p
      ON p.profile = u.profile
     AND p.resource_name = 'PASSWORD_VERIFY_FUNCTION'
    JOIN dba_profiles dp
      ON dp.profile = 'DEFAULT'
     AND dp.resource_name = 'PASSWORD_VERIFY_FUNCTION'
    ORDER BY u.profile
  }).column('profile_function')

  if profile_functions.empty?
    describe 'There are no user profiles, therefore this control is NA' do
      skip 'There are no user profiles, therefore this control is NA'
    end
  else
    profile_functions.each do |profile_function|
      profile, effective_function = profile_function.to_s.split('|', 2)
      effective_function = effective_function.to_s.strip

      describe "Profile #{profile}: effective PASSWORD_VERIFY_FUNCTION (#{effective_function})" do
        subject { effective_function.upcase }
        # A null/unset verify function is a finding. Oracle stores an unset
        # function as the string 'NULL' in DBA_PROFILES.LIMIT.
        it { should_not be_empty }
        it { should_not cmp 'NULL' }
        it { should be_in approved_password_verify_functions }
      end
    end
  end
end
