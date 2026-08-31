control 'SV-270554' do
  title 'Unused database components that are integrated in the database management system (DBMS) and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide, or install by default, any functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plug-ins not related to requirements or providing a wide array of functionality not required for the mission.

Applications must adhere to the principles of least functionality by providing only essential capabilities.

Unused, unnecessary DBMS components increase the attack vector for the DBMS by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled.'
  desc 'check', "Run this query to check to verify what integrated components are installed in the database:

SELECT parameter, value
from v$option
where parameter in 
(
'Data Mining',
'Oracle Database Extensions for .NET',
'OLAP',
'Partitioning',
'Real Application Testing'
);

This will return all of the relevant database options and their status. TRUE means that the option is installed. If the option is not installed, the option will be set to FALSE.

Review the options and check the system documentation to verify what is required. If all listed components are authorized to be in use, this is not a finding.

If any unused components or features are listed by the query as TRUE, this is a finding."
  desc 'fix', 'In the system documentation list the integrated components required for operation of applications that will be accessing the DBMS.

For Oracle Database 12.1 and higher, only the following components can be enabled/disabled:

Oracle Data Mining (dm)
Oracle Database Extensions for .NET (ode_net)
Oracle OLAP (olap)
Oracle Partitioning (partitioning)
Real Application Testing (rat)

Use the chopt utility (an Oracle-supplied operating system command that resides in the <Oracle Home path>/bin directory) to disable each option that should not be available. The command format is 
chopt <enable|disable> <option>
where <option> is any of the abbreviations in parentheses in the list above. For example, to disable Real Application Testing, issue the following command at an OS prompt:

chopt disable rat

Restart the Oracle service.

Refer to My Oracle Support Document 948061.1 for more on the chopt command.'
  impact 0.5
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag gid: 'V-270554'
  tag rid: 'SV-270554r1065221_rule'
  tag stig_id: 'O19C-00-013100'
  tag fix_id: 'F-74488r1064939_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a', 'Rev_4']
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

  # Only components whose value is TRUE are actually installed/enabled. The STIG
  # check: "TRUE means that the option is installed... If any unused components or
  # features are listed by the query as TRUE, this is a finding." Filtering on
  # value='TRUE' in SQL ensures a component reported FALSE (not installed) is not
  # flagged; selecting only the parameter column then yields the installed set.
  list_of_installed_components_integrated_into_dbms = sql.query("SELECT parameter
  from v$option
  where value = 'TRUE'
  and parameter in
  (
  'Data Mining',
  'Oracle Database Extensions for .NET',
  'OLAP',
  'Partitioning',
  'Real Application Testing'
  );").column('parameter').uniq
  if list_of_installed_components_integrated_into_dbms.empty?
    # No integrated components are enabled (all report value=FALSE), so there is
    # nothing to disable and the control passes. A passing describe is used rather
    # than a conditional `impact 0.0` — `impact` is a control-definition method and
    # calling it inside the runtime body raises NoMethodError.
    describe 'Unused integrated Oracle database components that are enabled (value=TRUE)' do
      subject { list_of_installed_components_integrated_into_dbms }
      it { should be_empty }
    end
  else
    list_of_installed_components_integrated_into_dbms.each do |component|
      describe "The installed oracle database components integrated into the DBMS: #{component}" do
        subject { component }
        it { should be_in input('allowed_oracledb_components_integrated_into_dbms') }
      end
    end
  end
end
