control 'SV-270533' do
  title 'Oracle application administration roles must be disabled if not
  required and authorized.'
  desc 'Application administration roles, which are assigned system or
  elevated application object privileges, must be protected from default
  activation. Application administration roles are determined by system privilege
  assignment (create / alter / drop user) and application user role ADMIN OPTION
  privileges.'
  desc 'check', "Run the SQL query:

select grantee, granted_role from dba_role_privs
where default_role='YES'
and granted_role in
(select grantee from dba_sys_privs where upper(privilege) like '%USER%') 
and grantee not in
(<list of nonapplicable accounts>)
and grantee not in (select distinct owner from dba_tables)
and grantee not in
(select distinct username from dba_users where upper(account_status) like
'%LOCKED%');

With respect to the list of special accounts that are excluded from this requirement, it is expected that the database administrator (DBA) will maintain the list to suit local circumstances, adding special accounts as necessary and removing any that are not supposed to be in use in the Oracle deployment that is under review.

Review the list of accounts reported for this check and ensures that they are authorized application administration roles.

If any are not authorized application administration roles, this is a finding."
  desc 'fix', 'For each role assignment returned, issue:

  From SQL*Plus:

  alter user [username] default role all except [role];

  If the user has more than one application administration role assigned, then
  remove assigned roles from default assignment and assign individually the
  appropriate default roles.'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270533'
  tag rid: 'SV-270533r1065215_rule'
  tag stig_id: 'O19C-00-010100'
  tag fix_id: 'F-74467r1064876_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b', 'Rev_4']
  tag 'false_negatives'
  tag 'false_positives'
  tag 'documentable'
  tag 'mitigations'
  tag 'severity_override_guidance'
  tag 'potential_impacts'
  tag 'third_party_tools'
  tag 'mitigation_controls'
  tag 'responsibility'
  tag 'ia_controls'
  tag 'check'
  tag 'fix'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), port: input('port'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  users_with_dba_role = sql.query("select grantee from dba_role_privs
  where default_role='YES'
  and granted_role in
  (select grantee from dba_sys_privs where upper(privilege) like '%USER%')
  and grantee not in (select distinct owner from dba_tables)
  and grantee not in
  (select distinct username from dba_users where upper(account_status) like
   '%LOCKED%');").column('grantee').uniq
  # An empty result means no account holds the DBA role by default — the
  # requirement is fully satisfied, so this is a PASS (not N/A). `all` is
  # vacuously true on an empty array; any grantee outside the org-defined
  # allowlist is still a finding.
  describe 'Accounts holding the DBA role by default' do
    subject { users_with_dba_role }
    it { should all(be_in input('allowed_users_dba_role')) }
  end
end
