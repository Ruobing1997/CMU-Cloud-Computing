package autoscaling;

import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.model.Subnet;
import com.amazonaws.services.elasticloadbalancingv2.AmazonElasticLoadBalancing;
import com.amazonaws.services.elasticloadbalancingv2.model.LoadBalancer;
import com.amazonaws.services.elasticloadbalancingv2.model.Tag;
import com.amazonaws.services.elasticloadbalancingv2.model.TargetGroup;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static autoscaling.AutoScale.PROJECT_VALUE;


/**
 * ELB resources class.
 */
public final class Elb {
    /**
     * ELB Tags.
     */
    public static final List<Tag> ELB_TAGS_LIST = Arrays.asList(
            new Tag().withKey("Project").withValue(PROJECT_VALUE));

    /**
     * Unused default constructor.
     */
    private Elb() {
    }

    /**
     * Create a target group.
     *
     * @param elb elb client
     * @param ec2 ec2 client
     * @return target group instance
     */
    public static TargetGroup createTargetGroup(
            final AmazonElasticLoadBalancing elb,
            final AmazonEC2 ec2) {
        //TODO: Create Target Group
        return null;
    }

    /**
     * Create a load balancer.
     *
     * @param elb             ELB client
     * @param ec2             EC2 client
     * @param securityGroupId Security group ID
     * @param targetGroupArn  target group ARN
     * @return Load balancer instance
     */
    public static LoadBalancer createLoadBalancer(
            final AmazonElasticLoadBalancing elb,
            final AmazonEC2 ec2,
            final String securityGroupId,
            final String targetGroupArn) {

        //TODO: 
        //  - Get Subnets for us-east-1 region
        //  - Create Load Balancer
        //  - Attach Listener
        return null;

    }

    /**
     * Delete the load balancer.
     * @param elb             LoadBalancing client
     * @param loadBalancerArn load balancer ARN
     */
    public static void deleteLoadBalancer(final AmazonElasticLoadBalancing elb,
                                          final String loadBalancerArn) {
       //TODO: Delete LoadBalancer
    }

    /**
     * Delete Target Group.
     *
     * @param elb            ELB Client
     * @param targetGroupArn target Group ARN
     */
    public static void deleteTargetGroup(final AmazonElasticLoadBalancing elb,
                                         final String targetGroupArn) {
       //TODO: Delete Target Group
    }
}
