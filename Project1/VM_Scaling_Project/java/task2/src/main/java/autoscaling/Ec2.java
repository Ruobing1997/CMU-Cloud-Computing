package autoscaling;

import static autoscaling.AutoScale.PROJECT_VALUE;

import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.Tag;
import com.amazonaws.services.ec2.model.TagSpecification;
import com.amazonaws.services.ec2.model.Vpc;

import java.util.Arrays;
import java.util.List;

/**
 * Class to manage EC2 resources.
 */
public final class Ec2 {

    /**
     * EC2 Tags.
     */
    public static final List<Tag> EC2_TAGS_LIST = Arrays.asList(
            new Tag().withKey("Project").withValue(PROJECT_VALUE));

    /**
     * Unused default constructor.
     */
    private Ec2() {
    }

    /**
     * Launch an Ec2 Instance.
     *
     * @param ec2                EC2Client
     * @param tagSpecification   TagsSpecified to create instance
     * @param amiId              amiId
     * @param instanceType       Type of instance
     * @param securityGroupName  Security Group
     * @param detailedMonitoring With Detailed Monitoring Enabled
     * @return Instance object
     */
    public static Instance launchInstance(final AmazonEC2 ec2,
                                          final TagSpecification tagSpecification,
                                          final String amiId,
                                          final String instanceType,
                                          final String securityGroupName,
                                          final Boolean detailedMonitoring) {
        //TODO: Launch EC2 instances 
        // - Create a Run Instance Request
        // - Wait for VM to start running
        // - Return the Object Reference of the Instance just Launched
        // - TODO Create Instance and wait for it to start running
        return null;
    }

    /**
     * Get instance object by ID.
     *
     * @param ec2        Ec2 client instance
     * @param instanceId isntance ID
     * @return Instance Object
     */
    private static Instance getInstance(final AmazonEC2 ec2,
                                        final String instanceId) {
        //TODO: get Instance by ID
        return null;
    }

    /**
     * Get or create a security group and allow all HTTP inbound traffic.
     *
     * @param ec2               EC2 Client
     * @param securityGroupName the name of the security group
     * @param vpcId             the ID of the VPC
     * @return ID of security group
     */
    static String getOrCreateHttpSecurityGroup(final AmazonEC2 ec2,
                                               final String securityGroupName,
                                               final String vpcId) {
        //TODO: Get or create Security Group
        //TODO: Allow all HTTP inbound traffic for the security group
        return null;
    }

    /**
     * Get the default VPC.
     * <p>
     * With EC2-Classic, your instances run in a single, flat network that you share with other customers.
     * With Amazon VPC, your instances run in a virtual private cloud (VPC) that's logically isolated to your AWS account.
     * <p>
     * The EC2-Classic platform was introduced in the original release of Amazon EC2.
     * If you created your AWS account after 2013-12-04, it does not support EC2-Classic,
     * so you must launch your Amazon EC2 instances in a VPC.
     * <p>
     * By default, when you launch an instance, AWS launches it into your default VPC.
     * Alternatively, you can create a non-default VPC and specify it when you launch an instance.
     *
     * @param ec2 EC2 Client
     * @return the default VPC object
     */
    public static Vpc getDefaultVPC(final AmazonEC2 ec2) {
        //TODO: get region default VPC ID
        return null;
    }

    /**
     * Fetch a Security Group's ID by Name.
     *
     * @param ec2       Ec2 client
     * @param groupName group name String
     * @return group ID
     */
    static String getSecurityGroupId(final AmazonEC2 ec2,
                                     final String groupName) {
        //TODO: Get Security Group ID
        return null;
    }

    /**
     * Delete a Security group.
     *
     * @param ec2              ec2 client
     * @param elbSecurityGroup security group name
     */
    static void deleteSecurityGroup(final AmazonEC2 ec2,
                                    final String elbSecurityGroup) {
        //TODO: Delete the security group
    }
}
