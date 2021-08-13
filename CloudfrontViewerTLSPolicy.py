from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class CloudfrontViewerTLSPolicy(BaseResourceCheck):
    def __init__(self):
        name = "Ensure cloudfront distribution ViewerCertificate minimumProtocolVersion is TLS v1.2 or above"
        id = "CUSTOM_CF_VIEWER_TLS_1.2"
        supported_resources = ['AWS::CloudFront::Distribution']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
            Looks for MinimumProtocolVersion configuration at cloudfront distributions:
                https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-viewercertificate.html
                https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html#secure-connections-supported-ciphers
        :param conf: cloudfront configuration
        :return: <CheckResult>
        """

        if 'Properties' in conf.keys():
            if 'DistributionConfig' in conf['Properties'].keys():
                if 'ViewerCertificate' in conf['Properties']['DistributionConfig'].keys():
                    protocol = str(conf['Properties']['DistributionConfig']['ViewerCertificate']['minimumProtocolVersion'])
                    if protocol == 'TLSv1.2_2021' or protocol == 'TLSv1.2_2019':
                    # You can customize your policy:
                    #   if protocol.startswith('TLSv1.2_'):
                    #   if conf['Properties']['DistributionConfig']['ViewerCertificate']['minimumProtocolVersion'] == 'TLSv1.2_2021':
                        return CheckResult.PASSED
        return CheckResult.FAILED

check = CloudfrontViewerTLSPolicy()
