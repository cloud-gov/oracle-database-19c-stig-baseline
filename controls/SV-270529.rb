control 'SV-270529' do
  title 'Oracle roles granted using the WITH ADMIN OPTION must not be granted
  to unauthorized accounts.'
  desc "The WITH ADMIN OPTION allows the grantee to grant a role to another database account. Best security practice restricts the privilege of assigning privileges to authorized personnel. Authorized personnel include database administrators (DBAs), object owners, and application administrators (where designed and included in the application's functions). Restricting privilege-granting functions to authorized accounts can help decrease mismanagement of privileges and wrongful assignments to unauthorized accounts."
  desc 'check', "A default Oracle Database installation provides a set of predefined administrative accounts and nonadministrative accounts. These are accounts that have special privileges required to administer areas of the database, such as the CREATE ANY TABLE or ALTER SESSION privilege or EXECUTE privileges on packages owned by the SYS schema. The default tablespace for administrative accounts is either SYSTEM or SYSAUX. Nonadministrative user accounts only have the minimum privileges needed to perform their jobs. Their default tablespace is USERS.

To protect these accounts from unauthorized access, the installation process expires and locks most of these accounts, except where noted below. The database administrator is responsible for unlocking and resetting these accounts, as required.

Non-Administrative Accounts - Expired and locked:
APEX_PUBLIC_USER, DIP, FLOWS_040100*, FLOWS_FILES, MDDATA, SPATIAL_WFS_ADMIN_USR, XS$NULL

Administrative Accounts - Expired and Locked:
ANONYMOUS, CTXSYS, EXFSYS, LBACSYS, MDSYS, OLAPSYS, ORACLE_OCM, ORDDATA, OWBSYS, ORDPLUGINS, ORDSYS, OUTLN, SI_INFORMTN_SCHEMA, SPATIAL_CSW_ADMIN_USR, WK_TEST, WK_SYS, WKPROXY, WMSYS, XDB

Administrative Accounts - Open:
DBSNMP, MGMT_VIEW, SYS, SYSMAN, SYSTEM

*Subject to change based on version installed.

Run the SQL statement:

select grantee||': '||granted_role from dba_role_privs
where grantee not in
(<list of nonapplicable accounts>)
and admin_option = 'YES' 
and grantee not in
(select distinct owner from dba_objects)
and grantee not in
(select grantee from dba_role_privs
where granted_role = 'DBA')
order by grantee;

(With respect to the list of special accounts that are excluded from this requirement, it is expected that the DBA will maintain the list to suit local circumstances, adding special accounts as necessary and removing any that are not supposed to be in use in the Oracle deployment that is under review.)

Review the system documentation to confirm any grantees listed are information system security officer (ISSO)-authorized DBA accounts or application administration roles.

If any grantees listed are not authorized and documented, this is a finding."
  desc 'fix', 'Revoke assignment of roles with the WITH ADMIN OPTION from unauthorized grantees and regrant them without the option if required.

SQL statements to remove the admin option from an unauthorized grantee:
revoke <role name> from <grantee>;
grant <role name> to <grantee>;

Restrict use of the WITH ADMIN OPTION to authorized administrators.

Document authorized role assignments with the WITH ADMIN OPTION in the system documentation.'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270529'
  tag rid: 'SV-270529r1065268_rule'
  tag stig_id: 'O19C-00-009700'
  tag fix_id: 'F-74463r1064864_fix'
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

  users_with_admin_option = sql.query("select grantee from dba_role_privs
    where admin_option = 'YES'
    and grantee not in (
      'XDB', 'SYSTEM', 'SYS', 'LBACSYS', 'DVSYS', 'DVF', 'SYSMAN_RO',
      'SYSMAN_BIPLATFORM', 'SYSMAN_MDS', 'SYSMAN_OPSS', 'SYSMAN_STB', 'DBSNMP',
      'SYSMAN', 'APEX_040200', 'WMSYS', 'SYSDG', 'SYSBACKUP',
      'SPATIAL_WFS_ADMIN_USR', 'SPATIAL_CSW_ADMIN_US', 'GSMCATUSER', 'OLAPSYS',
      'SI_INFORMTN_SCHEMA', 'OUTLN', 'ORDSYS', 'ORDDATA', 'OJVMSYS',
      'ORACLE_OCM', 'MDSYS', 'ORDPLUGINS', 'GSMADMIN_INTERNAL', 'MDDATA',
      'FLOWS_FILES', 'DIP', 'CTXSYS', 'AUDSYS', 'APPQOSSYS', 'APEX_PUBLIC_USER',
      'ANONYMOUS', 'SPATIAL_CSW_ADMIN_USR', 'SYSKM', 'SYSMAN_TYPES', 'MGMT_VIEW',
      'EUS_ENGINE_USER', 'EXFSYS', 'SYSMAN_APM',
      'FLOWS_040100', 'OWBSYS', 'WKPROXY', 'WK_SYS', 'WK_TEST', 'XS$NULL',
      'DBA', 'PDB_DBA', 'RECOVERY_CATALOG_OWNER_VPD'
    )
    and grantee not in
    (select distinct owner from dba_objects)
    and grantee not in
    (select grantee from dba_role_privs
     where granted_role = 'DBA')
    order by grantee;").column('grantee').uniq
  # DISA check: exclude the Oracle-supplied predefined administrative accounts and
  # roles (the STIG's '<list of nonapplicable accounts>'), then any REMAINING
  # grantee holding a role WITH ADMIN OPTION must be an org-authorized admin
  # (allowed_dbadmin_users) or it is a finding. An empty result means the
  # requirement is fully satisfied — this is a PASS (not N/A); `all` is vacuously
  # true on an empty array.
  describe 'Accounts holding a role WITH ADMIN OPTION' do
    subject { users_with_admin_option }
    it { should all(be_in input('allowed_dbadmin_users')) }
  end
end
