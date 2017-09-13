"""This template provides functions for missing resources in CloudFormation for IPv6 functionality

Currently it provides:
    Custom::VPCCidrBlockPrefix: Mechanism to get the prefix information from an AWS::EC2::VPCCidrBlock resource.
        Properties:
            VpcAssociationId: Assoication ID for the VPC.
        Returns:
            Prefix: 2001:db8:cafe:4200::/56
            PrefixLength: 56
            TruncatedPrefix: 2001:db8:cafe:42
    Custom::SubnetModifyAssociateIpv6AddressOnCreation: Mechansim to set AssignIpv6AddressOnCreation on a Subnet.
        Properties:
            SubnetId: Id of Subnet you wish to modify
            AssignIpv6AddressOnCreation: True | False
    Custom::EgressOnlyGateway: Resource to create and manage an EgressOnlyGateway
        Properties:
            VpcId: ID of the VPC to attach the Egress Only Gateway
        Returns:
            EgressOnlyGatewayId: Id of the EgressOnlyGateway
    Custom::EgressOnlyGatewayRoute: Resource to create and manage a Route that contains an Egress Only Gateway
        Properties:
            RouteTableId: Id of the route table you wish to modify
            DestinationIpv6CidrBlock: Block to use for destination match (e.g. ::/0)
            EgressOnlyInternetGatewayId: Id of the EgressOnlyInternetGateway
    Custom::ElasticLoadBalancerV2SetIPAddressType: Mechanism to set IP Address Type for an ELBv2
        Properties:
            LoadBalancerArn: ARN of the ELBv2
            IpAddressType: ipv4 | dualstack
    Custom::GetIpv6Address: Mechanism to get the first IPv6 address of the first ENI on an instance
        Properties:
            InstanceId: Id of the instance
        Returns:
            Ipv6Address: Ipv6 Address of the instance

"""

import accustom
from functools import wraps
import boto3
import logging
from uuid import uuid4 as uuid
import re
import ipaddress
import time
import six

logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.DEBUG)

@accustom.rdecorator(decoratorHandleDelete=True,expectedProperties=['VpcAssociationId'])
def VPCCidrBlockPrefix(event, context):
    # Attempt the API call
    response = event['ec2_client'].describe_vpcs(Filters=[
        {
            'Name':'ipv6-cidr-block-association.association-id',
            'Values':[event['ResourceProperties']['VpcAssociationId']]
        },
        {
            'Name':'ipv6-cidr-block-association.state',
            'Values':['associating','associated']
        }])

    # Confirm a VPC was actually returned
    if not response['Vpcs']:
        errMsg = 'AssociationId %s not found' % event['ResourceProperties']['VpcAssociationId']
        logger.error(errMsg)
        return accustom.ResponseObject(reason=errMsg,responseStatus=accustom.Status.FAILED,physicalResourceId=event['PhysicalResourceId'])

    associationSet = response['Vpcs'][0]['Ipv6CidrBlockAssociationSet']
    prefix = None
    for index, item in enumerate(associationSet):
        if event['ResourceProperties']['VpcAssociationId'] == item['AssociationId']:
            prefix = item['Ipv6CidrBlock']
            break

    # Return an error if we could not find the Association
    if prefix is None:
        errMsg = 'Association %s not found'
        logger.error(errMsg)
        return accustom.ResponseObject(reason=errMsg,responseStatus=accustom.Status.FAILED,physicalResourceId=event['PhysicalResourceId'])

    logger.debug('Found prefix for association %s: %s' %(event['ResourceProperties']['VpcAssociationId'], prefix))

    # Spliting the prefix into an address and length component
    address, prefixLength = prefix.split('/')

    # We need to explode the address into long form and reverse
    reversedExplodedAddress = ipaddress.IPv6Address(six.text_type(address)).exploded[::-1]

    # Putting this error here so the exception of an invalid address will be thrown first.
    if int(prefixLength) % 4 != 0:
        errMsg = 'Prefix %s has a prefix length not a nibble boundary of %s' % (prefix, prefixLength)
        logger.error(errMsg)
        return accustom.ResponseObject(reason=errMsg,responseStatus=accustom.Status.FAILED,physicalResourceId=physicalResourceId)

    # Now we need to determine how many characters to remove
    charactersToRemove = (128 - int(prefixLength)) / 4
    charactersToRemove = charactersToRemove + (charactersToRemove / int(4)) # Include Colons

    # Remove right number of characters and reverse again
    trunPrefix = reversedExplodedAddress[ : int(charactersToRemove) - 1 : -1]
    logger.debug('Determined truncated prefix to be %s for prefix of length %s' % (trunPrefix, prefixLength))

    responseData = {
            'Prefix': prefix,
            'PrefixLength': prefixLength,
            'TruncatedPrefix': trunPrefix
            }

    return accustom.ResponseObject(data=responseData,physicalResourceId=event['PhysicalResourceId'])

@accustom.rdecorator(expectedProperties=['SubnetId','AssignIpv6AddressOnCreation'])
def SubnetModifyAssociateIpv6AddressOnCreation(event, context):
    if event['RequestType'] == accustom.RequestType.DELETE:
        # We want to force disable of the setting on delete to allow other resources to delete.
        ipv6OnCreation = False
    elif event['ResourceProperties']['AssignIpv6AddressOnCreation'] in (True, False):
        ipv6OnCreation = event['ResourceProperties']['AssignIpv6AddressOnCreation']
    elif event['ResourceProperties']['AssignIpv6AddressOnCreation'].lower() in ('true', 'yes', 'on'):
        ipv6OnCreation = True
    elif event['ResourceProperties']['AssignIpv6AddressOnCreation'].lower() in ('false', 'no', 'off'):
        ipv6OnCreation = False
    else:
        errMsg = 'Property AssignIpv6AddressOnCreation had invalid value of %s, supported values: True | False' %  event['ResourceProperties']['AssignIpv6AddressOnCreation']
        logger.error(errMsg)
        return accustom.ResponseObject(reason=errMsg,responseStatus=accustom.Status.FAILED,physicalResourceId=event['PhysicalResourceId']) 

    response = event['ec2_client'].modify_subnet_attribute(
            SubnetId=event['ResourceProperties']['SubnetId'],
            AssignIpv6AddressOnCreation={'Value': ipv6OnCreation})

    logger.debug('Successfully changed subnet attribute AssignIpv6AddressOnCreation to %s' % str(ipv6OnCreation) )
    time.sleep(5) # wait 5 seconds to ensure change is reflected

    return accustom.ResponseObject(physicalResourceId=event['PhysicalResourceId'])

@accustom.rdecorator(expectedProperties=['VpcId'])
def EgressOnlyGateway(event, context):
    physicalResourceId = event['PhysicalResourceId']
    if event['RequestType'] == accustom.RequestType.DELETE:
        response = event['ec2_client'].delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=physicalResourceId)
        if not response['ReturnCode']:
            errMsg = 'Delete request failed of EgressOnlyInternetGateway'
            logger.error(errMsg)
            return accustom.ResponseObject(reason=errMsg,responseStatus=accustom.Status.FAILED,physicalResourceId=physicalResourceId)
        responseData = None

    else:
        # Attempt the API call
        response = event['ec2_client'].create_egress_only_internet_gateway(VpcId=event['ResourceProperties']['VpcId'])
        physicalResourceId = response['EgressOnlyInternetGateway']['EgressOnlyInternetGatewayId']

        attached = False
        included = False
        for index, item in enumerate(response['EgressOnlyInternetGateway']['Attachments']):
            if item['VpcId'] == event['ResourceProperties']['VpcId']:
                included = True
                if item['State'] == 'attached': attached = True
                break

        assert included # Should be true!
        if not attached:
            # Check again 5 times with 2 seconds in between
            for i in range(0,4):
                included = False
                time.sleep(2)
                response = event['ec2_client'].describe_egress_only_internet_gateways(
                                EgressOnlyInternetGatewayIds=[physicalResourceId],
                                MaxResults=1)
                for index,item in response['EgressOnlyInternetGateways'][0]['Attachments']:
                    if item['VpcId'] == event['ResourceProperties']['VpcId']:
                        included = True
                        if item['State'] == 'attached': attached = True
                        break

                assert included # Should be true!

                # Break loop so we don't sleep and describe again
                if attached is True: break

        responseData = {
                'EgressOnlyGatewayId' : physicalResourceId
                }

    return accustom.ResponseObject(data=responseData,physicalResourceId=physicalResourceId)

@accustom.rdecorator(expectedProperties=['RouteTableId','DestinationIpv6CidrBlock','EgressOnlyInternetGatewayId'])
def EgressOnlyGatewayRoute(event, context):
    if event['RequestType'] == accustom.RequestType.DELETE:
        response = event['ec2_client'].delete_route(
                RouteTableId=event['ResourceProperties']['RouteTableId'],
                DestinationIpv6CidrBlock=event['ResourceProperties']['DestinationIpv6CidrBlock']
                )
    else:
        response = event['ec2_client'].create_route(
                RouteTableId=event['ResourceProperties']['RouteTableId'],
                DestinationIpv6CidrBlock=event['ResourceProperties']['DestinationIpv6CidrBlock'],
                EgressOnlyInternetGatewayId=event['ResourceProperties']['EgressOnlyInternetGatewayId']
                )

        if not response['Return']:
            errMsg = 'Create request failed of EC2 Route'
            logger.error(errMsg)
            return accustom.ResponseObject(reason=errMsg,responseStatus=accustom.Status.FAILED,physicalResourceId=event['PhysicalResourceId'])

    return accustom.ResponseObject(physicalResourceId=event['PhysicalResourceId'])

@accustom.rdecorator(decoratorHandleDelete=True,expectedProperties=['LoadBalancerArn','IpAddressType'])
def ElasticLoadBalancerV2SetIPAddressType(event, context):
    response = event['elbv2_client'].set_ip_address_type(
            LoadBalancerArn=event['ResourceProperties']['LoadBalancerArn'],
            IpAddressType=event['ResourceProperties']['IpAddressType'])

    time.sleep(5) # wait 5 seconds to ensure change is reflected

    return accustom.ResponseObject(physicalResourceId=event['PhysicalResourceId'])

@accustom.rdecorator(decoratorHandleDelete=True,expectedProperties=['InstanceId'])
def GetIpv6Address(event, context):
    response = event['ec2_client'].describe_instances(InstanceIds=[event['ResourceProperties']['InstanceId']])

    responseData = {
        'Ipv6Address' : response['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0]['Ipv6Addresses'][0]['Ipv6Address']
        }

    return accustom.ResponseObject(data=responseData,physicalResourceId=event['PhysicalResourceId'])

@accustom.decorator(enforceUseOfClass=True)
def vpc_ipv6_cfn(event, context=None):
    # Default context to None in case testing locally
    resourceType = event['ResourceType']
    if 'PhysicalResourceId' not in event:
        event['PhysicalResourceId'] = uuid().hex
    BackupResult = accustom.ResponseObject(reason='Custom Resource %s did not return' % event['ResourceType'],responseStatus=accustom.Status.FAILED,physicalResourceId=event['PhysicalResourceId'])

    # Get Stack Region from the ARN
    event['regionName'] = event['StackId'].split(':')[3]

    # Init Clients in Region
    event['ec2_client'] = boto3.client('ec2',region_name=event['regionName'])
    event['elbv2_client'] = boto3.client('elbv2',region_name=event['regionName'])

    if resourceType == "Custom::VPCCidrBlockPrefix":
        return VPCCidrBlockPrefix(event, context)

    elif resourceType == "Custom::SubnetModifyAssociateIpv6AddressOnCreation":
        return SubnetModifyAssociateIpv6AddressOnCreation(event, context)

    elif resourceType == "Custom::EgressOnlyGateway":
        return EgressOnlyGateway(event, context)

    elif resourceType == "Custom::EgressOnlyGatewayRoute":
        return EgressOnlyGatewayRoute(event, context)

    elif resourceType == "Custom::ElasticLoadBalancerV2SetIPAddressType":
        return ElasticLoadBalancerV2SetIPAddressType(event, context)

    elif resourceType == "Custom::GetIpv6Address":
        return GetIpv6Address(event,context)

    else:
        return accustom.ResponseObject(reason='ResourceType "%s" is not supported' % event['ResourceType'],responseStatus=accustom.Status.FAILED,physicalResourceId=event['PhysicalResourceId'])

    # Safety Net
    return BackupResult
