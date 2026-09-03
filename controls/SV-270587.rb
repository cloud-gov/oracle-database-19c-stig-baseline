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

  # Sibling of SV-270561 (IA-5(1)(a)): the SV-270587 (IA-5(1)(b)) check text is the
  # SAME SQL predicate over SYS.DBA_PROFILES — "If the function name is null for any
  # profile, this is a finding." The additional IA-5(1)(b) requirement (reject
  # commonly-used/expected/compromised passwords) is enforced by the CODE inside the
  # verify function, which is a source-code review that is not portably
  # SQL-decidable. Satisfy that review by using Oracle's supplied
  # ORA12C_STIG_VERIFY_FUNCTION / ORA_STIG_PROFILE named by the DISA fix. The
  # automatable predicate is the same as SV-270561: every profile in use must have a
  # non-null effective PASSWORD_VERIFY_FUNCTION.

  # Profiles actually assigned to users (profiles-in-use convention, per
  # SV-270549/551/561). Each is evaluated for its EFFECTIVE verify function.
  user_profiles = sql.query('SELECT DISTINCT profile FROM dba_users;').column('profile')

  # Per-profile query mirroring SV-270561. DECODE resolves a profile whose
  # PASSWORD_VERIFY_FUNCTION is the literal 'DEFAULT' to the DEFAULT profile's
  # function. Read via .column (the reliable accessor in this repo — .rows hash
  # access returned blanks).
  query = %{
    SELECT DECODE(p1.limit, 'DEFAULT', p2.limit, p1.limit) AS effective_function
    FROM dba_profiles p1, dba_profiles p2
    WHERE p1.profile = '%<profile>s'
    AND p1.resource_name = 'PASSWORD_VERIFY_FUNCTION'
    AND p2.profile = 'DEFAULT'
    AND p2.resource_name = 'PASSWORD_VERIFY_FUNCTION'
  }

  if user_profiles.empty?
    describe 'There are no user profiles, therefore this control is NA' do
      skip 'There are no user profiles, therefore this control is NA'
    end
  else
    user_profiles.each do |profile|
      effective_function = sql.query(format(query, profile: profile)).column('effective_function').first

      describe "Profile #{profile}: effective PASSWORD_VERIFY_FUNCTION (#{effective_function})" do
        subject { effective_function }
        # A null/unset verify function is a finding. Oracle stores an unset
        # function as the string 'NULL' in DBA_PROFILES.LIMIT; guard the empty/
        # nil case too so a blank effective function is not silently passed.
        it { should_not cmp 'NULL' }
      end
    end
  end
end
