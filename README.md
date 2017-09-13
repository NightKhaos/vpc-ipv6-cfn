# vpc-ipv6-cfn

## Deprecated

**Note**: Previously this template relied on some public S3 buckets. I have stopped providing these buckets. Please review the new procedure, however, all of the functionality this template provides can be done natively. This is only provided so that legacy users are unaffected.

Custom Resource to provide the "missing pieces" when configuring IPv6 in VPCs

This custom resource is fairly easy to use, simply run the following script. You will need to provide an S3 bucket in the same region you wish to launch the template.

```bash
pip3 install -r src/requirements.txt -t src --no-deps
aws cloudformation package --template-file vpc-ipv6-cfn.template --s3-bucket $S3_BUCKET --output-template run.yml
aws cloudformation deploy --template-file run.yml --stack-name vpc-ipv6-cfn  --capabilities CAPABILITY_IAM 
```
One template is launched you can use the following resources:

## `Custom::VPCCidrBlockPrefix` 
Mechanism to get the prefix information from an AWS::EC2::VPCCidrBlock resource.

        Properties:
            VpcAssociationId: Assoication ID for the VPC.
        Returns:
            Prefix: 2001:db8:cafe:4200::/56
            PrefixLength: 56
            TruncatedPrefix: 2001:db8:cafe:42
            
 ## `Custom::SubnetModifyAssociateIpv6AddressOnCreation`
 Mechansim to set AssignIpv6AddressOnCreation on a Subnet.
 
    Properties:
            SubnetId: Id of Subnet you wish to modify
            AssignIpv6AddressOnCreation: True | False
            
## `Custom::EgressOnlyGateway`
Resource to create and manage an EgressOnlyGateway

        Properties:
            VpcId: ID of the VPC to attach the Egress Only Gateway
        Returns:
            EgressOnlyGatewayId: Id of the EgressOnlyGateway
## `Custom::EgressOnlyGatewayRoute`
Resource to create and manage a Route that contains an Egress Only Gateway

        Properties:
            RouteTableId: Id of the route table you wish to modify
            DestinationIpv6CidrBlock: Block to use for destination match (e.g. ::/0)
            EgressOnlyInternetGatewayId: Id of the EgressOnlyInternetGateway
    
## `Custom::ElasticLoadBalancerV2SetIPAddressType`
Mechanism to set IP Address Type for an ELBv2

        Properties:
            LoadBalancerArn: ARN of the ELBv2
            IpAddressType: ipv4 | dualstack

## `Custom::GetIpv6Address`
Mechanism to get the first IPv6 address of the first ENI on an instance

        Properties:
            InstanceId: Id of the instance
        Returns:
            Ipv6Address: Ipv6 Address of the instance
