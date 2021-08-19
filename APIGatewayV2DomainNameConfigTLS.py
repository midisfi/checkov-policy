from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class APIGatewayV2DomainNameTLSProtocol(BaseResourceCheck):
    def __init__(self):
        name = "Ensure API Gateway V2 SecurityPolicy is TLS v1.2 or better"
        id = "CUSTOM_APIGWV2_TLS_1.2"
        supported_resources = ['AWS::ApiGatewayV2::DomainName']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
            Ensures SecurityPolicy for custom domains is TLS v1.2 or better:
                https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigatewayv2-domainname-domainnameconfiguration.html#cfn-apigatewayv2-domainname-domainnameconfiguration-securitypolicy
                https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html
        :param conf: apigwv2 configuration
        :return: <CheckResult>
        """

        if 'Properties' in conf.keys():
            if 'DistributionConfig' in conf['Properties'].keys():
                if 'Origins' in conf['Properties']['DistributionConfig'].keys():
                    for origin in range(len(conf['Properties']['DistributionConfig']['Origins'])):
                        for item in range(len(conf['Properties']['DistributionConfig']['Origins'][origin]['customOriginConfig']['originSslProtocols']['items'])):
                            protocol = conf['Properties']['DistributionConfig']['Origins'][origin]['customOriginConfig']['originSslProtocols']['items']
                            if protocol and all(elem == 'TLSv1.2' for elem in protocol):
                                return CheckResult.PASSED
        return CheckResult.FAILED

check = APIGatewayV2DomainNameTLSProtocol()
