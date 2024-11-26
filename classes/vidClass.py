class VulnID:
    def __init__(self, vuln_num=None, status=None, finding_details=None, comments=None, rule_ver=None, severity=None, group_title=None, 
                 rule_id=None, rule_title=None, vuln_discuss=None, ia_controls=None, check_content=None, fix_text=None, false_positives=None,
                   false_negatives=None, documentable=None, mitigations=None, potential_impact=None, third_party_tools=None, mitigation_control=None, 
                   responsibility=None, security_override_guidance=None, check_content_ref=None, classification=None, stig_ref=None, 
                 targetkey=None, stig_uuid=None, legacy_id=None, cci_ref=None, severity_override=None, severity_justification=None):
        self.vuln_num = vuln_num
        self.status = status
        self.finding_details = finding_details
        self.comments = comments
        self.rule_ver = rule_ver
        self.severity = severity
        self.group_title = group_title
        self.rule_id = rule_id
        self.rule_title = rule_title
        self.vuln_discuss = vuln_discuss
        self.ia_controls = ia_controls
        self.check_content = check_content
        self.fix_text = fix_text
        self.false_positives = false_positives
        self.false_negatives = false_negatives
        self.documentable = documentable
        self.mitigations = mitigations
        self.potential_impact = potential_impact
        self.third_party_tools = third_party_tools
        self.mitigation_control = mitigation_control
        self.responsibility = responsibility
        self.security_override_guidance = security_override_guidance
        self.check_content_ref = check_content_ref
        self.classification = classification
        self.stig_ref = stig_ref
        self.targetkey = targetkey
        self.stig_uuid = stig_uuid
        self.legacy_id = legacy_id
        self.cci_ref = cci_ref
        self.severity_override = severity_override
        self.severity_justification = severity_justification

    # Getters
    def get_vuln_num(self):
        return self.vuln_num

    def get_status(self):
        return self.status

    def get_finding_details(self):
        return self.finding_details

    def get_comments(self):
        return self.comments

    def get_rule_ver(self):
        return self.rule_ver

    def get_severity(self):
        return self.severity

    def get_group_title(self):
        return self.group_title

    def get_rule_id(self):
        return self.rule_id

    def get_rule_title(self):
        return self.rule_title

    def get_vuln_discuss(self):
        return self.vuln_discuss

    def get_ia_controls(self):
        return self.ia_controls

    def get_check_content(self):
        return self.check_content

    def get_fix_text(self):
        return self.fix_text

    def get_false_positives(self):
        return self.false_positives

    def get_false_negatives(self):
        return self.false_negatives

    def get_documentable(self):
        return self.documentable

    def get_mitigations(self):
        return self.mitigations

    def get_potential_impact(self):
        return self.potential_impact

    def get_third_party_tools(self):
        return self.third_party_tools

    def get_mitigation_control(self):
        return self.mitigation_control

    def get_responsibility(self):
        return self.responsibility

    def get_security_override_guidance(self):
        return self.security_override_guidance

    def get_check_content_ref(self):
        return self.check_content_ref

    def get_classification(self):
        return self.classification

    def get_stig_ref(self):
        return self.stig_ref

    def get_targetkey(self):
        return self.targetkey

    def get_stig_uuid(self):
        return self.stig_uuid

    def get_legacy_id(self):
        return self.legacy_id

    def get_cci_ref(self):
        return self.cci_ref

    def get_severity_override(self):
        return self.severity_override

    def get_severity_justification(self):
        return self.severity_justification


class customerVulnID(VulnID):
    def __init__(self, vuln_num=None, host_ip=None, quarterly_audit=None, customer_system=None, customer_site=None, system_version=None, 
                 
                 status=None, finding_details=None, comments=None, 

                 rule_ver=None, severity=None, group_title=None, rule_id=None, rule_title=None, vuln_discuss=None, ia_controls=None, check_content=None,
                 fix_text=None, false_positives=None, false_negatives=None, documentable=None, mitigations=None, potential_impact=None, 
                 third_party_tools=None, mitigation_control=None, responsibility=None, security_override_guidance=None, check_content_ref=None, 
                 classification=None, stig_ref=None, targetkey=None, stig_uuid=None, legacy_id=None, cci_ref=None, severity_override=None, severity_justification=None):
        
        super().__init__(vuln_num, rule_ver, severity, group_title, rule_id, rule_title, 
                         vuln_discuss, ia_controls, check_content, fix_text, false_positives, false_negatives, documentable, 
                         mitigations, potential_impact, third_party_tools, mitigation_control, responsibility, security_override_guidance, 
                         check_content_ref, classification, stig_ref, targetkey, stig_uuid, legacy_id, cci_ref, severity_override, 
                         severity_justification)
        
        # Customer specific attributes - attributes of the genericVulnID class
        self.comments = comments
        self.status = status
        self.finding_details = finding_details
        # Customer specific attributes - new attributes
        self.host_ip = host_ip
        self.quarterly_audit = quarterly_audit
        self.customer_system = customer_system
        self.customer_site = customer_site
        self.system_version = system_version

    # Getters

        # Getters
    def get_vuln_num(self):
        return self.vuln_num

    def get_status(self):
        return self.status

    def get_finding_details(self):
        return self.finding_details

    def get_comments(self):
        return self.comments

    def get_rule_ver(self):
        return self.rule_ver

    def get_severity(self):
        return self.severity

    def get_group_title(self):
        return self.group_title

    def get_rule_id(self):
        return self.rule_id

    def get_rule_title(self):
        return self.rule_title

    def get_vuln_discuss(self):
        return self.vuln_discuss

    def get_ia_controls(self):
        return self.ia_controls

    def get_check_content(self):
        return self.check_content

    def get_fix_text(self):
        return self.fix_text

    def get_false_positives(self):
        return self.false_positives

    def get_false_negatives(self):
        return self.false_negatives

    def get_documentable(self):
        return self.documentable

    def get_mitigations(self):
        return self.mitigations

    def get_potential_impact(self):
        return self.potential_impact

    def get_third_party_tools(self):
        return self.third_party_tools

    def get_mitigation_control(self):
        return self.mitigation_control

    def get_responsibility(self):
        return self.responsibility

    def get_security_override_guidance(self):
        return self.security_override_guidance

    def get_check_content_ref(self):
        return self.check_content_ref

    def get_classification(self):
        return self.classification

    def get_stig_ref(self):
        return self.stig_ref

    def get_targetkey(self):
        return self.targetkey

    def get_stig_uuid(self):
        return self.stig_uuid

    def get_legacy_id(self):
        return self.legacy_id

    def get_cci_ref(self):
        return self.cci_ref

    def get_severity_override(self):
        return self.severity_override

    def get_severity_justification(self):
        return self.severity_justification
    
    # Setters

    def set_status(self, status):
        self.status = status

    def set_comments(self, comment):
        self.comments = comment

    def set_findings_details(self, finding_details):
        self.finding_details = finding_details

    def set_host_ip(self, host_ip):
        self.host_ip = host_ip

    def set_month_year(self, month_year):
        self.month_year = month_year

    def set_customer_name(self, customer_name):
        self.customer_name = customer_name

    def set_customer_site(self, customer_site):
        self.customer_site = customer_site

    def set_system_version(self, system_version):
        self.system_version = system_version