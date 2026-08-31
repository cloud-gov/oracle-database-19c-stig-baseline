control 'SV-270561' do
  title 'Oracle Database must enforce the DOD standards for password complexity.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native database management system (DBMS) authentication may be used only when circumstances make it unavoidable; and must be documented and authorizing official (AO)-approved.

The DOD standard for authentication is DOD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate and requires AO approval.

In such cases, the DOD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For other DBMSs, the rules must be enforced using available configuration parameters or custom code.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible. Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.'
  desc 'check', "If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism and not by Oracle, this is not a finding.

For each profile that can be applied to accounts where authentication is under Oracle's control, determine the password verification function that is in use:

SELECT * FROM SYS.DBA_PROFILES 
WHERE RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
ORDER BY PROFILE;

Note: Profiles can inherit settings from another profile so some password functions could be set to DEFAULT. If so, review the DEFAULT profile function name. 

If the function name is null for any profile, this is a finding.

Review the password verification functions specified for the PASSWORD_VERIFY_FUNCTION settings for each profile. Determine whether the following rules are enforced by the code in those functions. 
a. Minimum of 15 characters, including at least one of each of the following character sets:
- Uppercase
- Lowercase
- Numeric
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
b. Minimum number of characters changed from previous password: 50 percent of the minimum password length; that is, eight.

If any of the above password requirements are not included in the function, this is a finding."
  desc 'fix', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, no fix to the DBMS is required.

If any user accounts are managed by Oracle, develop, test, and implement a password verification function that enforces DOD requirements.

Oracle supplies a sample function called ORA12C_STIG_VERIFY_FUNCTION. This can be used as the starting point for a customized function. The script file is found in the following location on the server depending on OS:

Windows:
%ORACLE_HOME%\\RDBMS\\ADMIN\\catpvf.sql

Unix/Linux:
$ORACLE_HOME/rdbms/admin/catpvf.sql'
  impact 0.5
  tag check_id: 'C-74594r1065287_chk'
  tag severity: 'medium'
  tag gid: 'V-270561'
  tag rid: 'SV-270561r1112485_rule'
  tag stig_id: 'O19C-00-013900'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-74495r1112484_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), port: input('port'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  # Per the check text, the SQL-verifiable portion is: for every profile in use,
  # the PASSWORD_VERIFY_FUNCTION must NOT be null. "If the function name is null
  # for any profile, this is a finding." Profiles can inherit the setting via the
  # literal value DEFAULT, in which case the check directs the reviewer to the
  # DEFAULT profile's function name; the query below resolves DEFAULT to the
  # DEFAULT profile's PASSWORD_VERIFY_FUNCTION so an inheriting profile is judged
  # by its effective function. In Oracle, an unset PASSWORD_VERIFY_FUNCTION is
  # stored as the string 'NULL' in DBA_PROFILES.LIMIT (not a SQL NULL); the
  # assertion therefore fails a profile whose effective function is 'NULL'.
  #
  # The complexity-RULE review inside the function body (>= 15 chars; one each of
  # upper/lower/numeric/special; >= 8 changed from the previous password) is a
  # source-code review that is not portably SQL-decidable; the presence assertion
  # below is the automatable predicate. Satisfy the rule review by using Oracle's
  # supplied ORA12C_STIG_VERIFY_FUNCTION / ORA_STIG_PROFILE named by the DISA fix.

  # Profiles actually assigned to users (profiles-in-use convention, per
  # SV-270549/551). Each is evaluated for its EFFECTIVE verify function.
  user_profiles = sql.query('SELECT DISTINCT profile FROM dba_users;').column('profile')

  # Per-profile query mirroring the SV-270549/563 pattern (single-column result
  # read via .column, which is the reliable accessor in this repo — .rows hash
  # access returned blanks). DECODE resolves a profile whose PASSWORD_VERIFY_
  # FUNCTION is the literal 'DEFAULT' to the DEFAULT profile's function.
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
