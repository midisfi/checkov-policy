from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class Severity(BaseResourceCheck):
    def __init__(self):
        name = "Test severity"
        id = "SEVERITY"
        supported_resources = ['AWS::ApiGatewayV2::DomainName']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
            Test severity
        :param conf: apigwv2 configuration
        :return: <CheckResult>
        """

        if 'Properties' in conf.keys():
            if 'DomainNameConfigurations' in conf['Properties'].keys():
                for domainnameconfiguration in range(len(conf['Properties']['DomainNameConfigurations'])):
                    if 'SecurityPolicy' in conf['Properties']['DomainNameConfigurations'][domainnameconfiguration]:
                        if conf['Properties']['DomainNameConfigurations'][domainnameconfiguration]['SecurityPolicy'] != 'TLS_1_2':
                            return CheckResult.FAILED
        # If parameter is not found at all, pass check
        return CheckResult.PASSED

check = Severity()
