control 'SV-270547' do
  title 'Oracle Database must provide a mechanism to automatically remove or disable temporary user accounts after 72 hours.'
  desc 'Temporary application accounts could ostensibly be used in the event of a vendor support visit where a support representative requires a temporary unique account to perform diagnostic testing or conduct some other support related activity. When these types of accounts are created, there is a risk that the temporary account may remain in place and active after the support representative has left.

To address this, in the event temporary application accounts are required, the application must ensure accounts designated as temporary in nature must automatically terminate these accounts after a period of 72 hours. Such a process and capability greatly reduces the risk that accounts will be misused, hijacked, or data compromised.

Note that user authentication and account management should be done via an enterprise-wide mechanism whenever possible. Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.

Temporary database accounts must be automatically terminated after a 72-hour time period to mitigate the risk of the account being used beyond its original purpose or timeframe.'
  desc 'check', 'If the organization has a policy, consistently enforced, forbidding the creation of emergency or temporary accounts, this is not a finding.

If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

Check database management system (DBMS) settings, OS settings, and/or enterprise-level authentication/access mechanisms settings to determine if the site uses a mechanism whereby temporary are terminated after a 72-hour time period. If not, this is a finding.'
  desc 'fix', 'If using database mechanisms to satisfy this requirement, use a profile with a distinctive name (for example, TEMPORARY_USERS), so that temporary users can be easily identified. Whenever a temporary user account is created, assign it to this profile.

Create a job to lock accounts under this profile that are more than 72 hours old.'
  impact 0.5
  tag check_id: 'C-74580r1064917_chk'
  tag severity: 'medium'
  tag gid: 'V-270547'
  tag rid: 'SV-270547r1064919_rule'
  tag stig_id: 'O19C-00-012100'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-74481r1064918_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # No automated assertion is defined for this control: it requires manual review
  # of system documentation / organizational policy (or is not tenant-verifiable
  # on managed RDS). Emit an explicit skip so the control is reported as "not
  # reviewed" rather than silently passing with zero tests.
  describe "SV-270547: manual review required (no automated test defined)" do
    skip "SV-270547 requires manual review; no automated assertion is defined."
  end
end
