from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class CloudfrontOriginTLSProtocol(BaseResourceCheck):
    def __init__(self):
        name = "Ensure cloudfront distribution origin is accessed via TLS v1.2 or above"
        id = "CUSTOM_CF_ORIGIN_TLS_1.2"
        supported_resources = ['AWS::CloudFront::Distribution']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
           Ensures originProtocolPolicy for custom origins is TLS v1.2:
                https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-customoriginconfig.html
                https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesOriginSSLProtocols
                https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_OriginSslProtocols.html
        :param conf: cloudfront configuration
        :return: <CheckResult>
        """

        if 'Properties' in conf.keys():
            if 'DistributionConfig' in conf['Properties'].keys():
                if 'origins' in conf['Properties']['DistributionConfig'].keys():
                    for origin in range(len(conf['Properties']['DistributionConfig']['origins'])):
                        if 'originSslProtocols' in conf['Properties']['DistributionConfig']['origins'][origin]['customOriginConfig']['originSslProtocols'].keys() == 'TLSv1.2':
                               return CheckResult.PASSED
        return CheckResult.FAILED

check = CloudfrontOriginTLSProtocol()
