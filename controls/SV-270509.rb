control 'SV-270509' do
  title 'Oracle Database must provide an immediate real-time alert to appropriate support staff of all audit log failures.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

The appropriate support staff include, at a minimum, the information system security officer (ISSO) and the database administrator (DBA)/system administrator (SA).

A failure of database auditing will result in either the database continuing to function without auditing or in a complete halt to database operations. When audit processing fails, appropriate personnel must be alerted immediately to avoid further downtime or unaudited transactions.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

If Oracle Enterprise Manager is in use, the capability to issue such an alert is built in and configurable via the console so an alert can be sent to a designated administrator.'
  desc 'check', 'Review Oracle Database, OS, or third-party logging software settings to determine whether a real-time alert will be sent to the appropriate personnel when auditing fails for any reason.

If real-time alerts are not sent upon auditing failure, this is a finding.'
  desc 'fix', 'Configure logging software to send a real-time alert to appropriate personnel when auditing fails for any reason.

Oracle recommends the use of Oracle Enterprise Manager.'
  impact 0.5
  tag check_id: 'C-74542r1064803_chk'
  tag severity: 'medium'
  tag gid: 'V-270509'
  tag rid: 'SV-270509r1065202_rule'
  tag stig_id: 'O19C-00-006000'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag fix_id: 'F-74443r1064804_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']

  # No automated assertion is defined for this control: it requires manual review
  # of system documentation / organizational policy (or is not tenant-verifiable
  # on managed RDS). Emit an explicit skip so the control is reported as "not
  # reviewed" rather than silently passing with zero tests.
  describe "SV-270509: manual review required (no automated test defined)" do
    skip "SV-270509 requires manual review; no automated assertion is defined."
  end
end
