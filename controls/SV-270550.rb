control 'SV-270550' do
  title 'Oracle Database must set the maximum number of consecutive invalid logon attempts to three.'
  desc 'Anytime an authentication method is exposed, to allow for the use of an application, there is a risk that attempts will be made to obtain unauthorized access.

To defeat these attempts, organizations define the number of times a user account may consecutively fail a logon attempt. The organization also defines the period of time in which these consecutive failed attempts may occur.

By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

More recent brute force attacks make attempts over long periods of time to circumvent intrusion detection systems and system account lockouts based entirely on the number of failed logons that are typically reset after a successful logon.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible. Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.

Note also that a policy that places no limit on the length of the timeframe (for counting consecutive invalid attempts) does satisfy this requirement.'
  desc 'check', 'The limit on the number of consecutive failed logon attempts is defined in the profile assigned to a user.

Check the FAILED_LOGIN_ATTEMPTS value assigned to the profiles returned from this query:

SQL>SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES;

Check the setting for FAILED_LOGIN_ATTEMPTS. This is the number of consecutive failed logon attempts before locking the Oracle user account. If the value is greater than three on any of the profiles, this is a finding.'
  desc 'fix', 'Configure the database management system (DBMS) setting to specify the maximum number of consecutive failed logon attempts to three (or less):

ALTER PROFILE {PROFILE_NAME} LIMIT FAILED_LOGIN_ATTEMPTS 3;

ORA_STIG_PROFILE is available in DBA_PROFILES. 

Note: It is necessary to create a customized replacement for the password validation function, ORA12C_STIG_VERIFY_FUNCTION, if relying on this technique to verify password complexity.'
  impact 0.5
  tag check_id: 'C-74583r1064926_chk'
  tag severity: 'medium'
  tag gid: 'V-270550'
  tag rid: 'SV-270550r1112482_rule'
  tag stig_id: 'O19C-00-012400'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-74484r1112481_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), port: input('port'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  # Per the check text, a profile is a finding when FAILED_LOGIN_ATTEMPTS is
  # greater than the org-defined maximum consecutive invalid logon attempts
  # (three per the STIG; carried in the failed_logon_attempts input). UNLIMITED
  # is likewise a finding (it exceeds the bound). Assess every profile in use.
  query = %{
    SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE =
  '%<profile>s' AND RESOURCE_NAME = 'FAILED_LOGIN_ATTEMPTS'
  }

  user_profiles = sql.query('SELECT profile FROM dba_users;').column('profile').uniq

  user_profiles.each do |profile|
    failed_login_attempts = sql.query(format(query, profile: profile)).column('limit')

    describe "The oracle database failed login attempts limit for profile: #{profile}" do
      subject { failed_login_attempts }
      it { should_not cmp 'UNLIMITED' }
      it { should cmp <= input('failed_logon_attempts') }
    end
  end
  if user_profiles.empty?
    describe 'There are no user profiles, therefore this control is NA' do
      skip 'There are no user profiles, therefore this control is NA'
    end
  end
end
