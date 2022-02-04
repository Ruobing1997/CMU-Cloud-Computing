package autoscaling;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.autoscaling.AmazonAutoScaling;
import com.amazonaws.services.autoscaling.AmazonAutoScalingClientBuilder;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.Tag;
import com.amazonaws.services.elasticloadbalancingv2.AmazonElasticLoadBalancing;
import com.amazonaws.services.elasticloadbalancingv2
        .AmazonElasticLoadBalancingClientBuilder;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.ini4j.Ini;
import utilities.Configuration;

/**
 * Main AutoScaling Task class.
 */
public final class AutoScale {

    /**
     * Configuration file
     */
    final static Configuration configuration = new Configuration("auto-scaling-config.json");

    /**
     * Project Tag value.
     */
    public static final String PROJECT_VALUE = "vm-scaling";

    /**
     * HTTP Port.
     */
    static final Integer HTTP_PORT = 80;

    /**
     * LG Security group Name.
     */
    private static final String LG_SECURITY_GROUP =
            "";
    /**
     * ELB/ASG Security group Name.
     */
    static final String ELBASG_SECURITY_GROUP =
            "";

    /**
     * Load Generator AMI.
     */
    private static final String LOAD_GENERATOR_AMI_ID
            = configuration.getString("load_generator_ami");

    /**
     * Web Service AMI.
     */
    static final String WEB_SERVICE
            = configuration.getString("web_service_ami");

    /**
     * Instance Type Name.
     */
    static final String INSTANCE_TYPE
            = configuration.getString("instance_type");

    /**
     * Auto Scaling Target Group Name.
     */
    static final String AUTO_SCALING_TARGET_GROUP
            = configuration.getString("auto_scaling_target_group");;

    /**
     * Load Balancer Name.
     */
    static final String LOAD_BALANCER_NAME
            = configuration.getString("load_balancer_name");;

    /**
     * Launch Configuration Name.
     */
    static final String LAUNCH_CONFIGURATION_NAME
            = configuration.getString("launch_configuration_name");;

    /**
     * Auto Scaling group name.
     */
    static final String AUTO_SCALING_GROUP_NAME
            = configuration.getString("auto_scaling_group_name");;

    /**
     * Tags list.
     */
    static final List<Tag> TAGS_LIST = Arrays.asList(
            new Tag().withKey("project").withValue(PROJECT_VALUE));

    /**
     * Whether the Load Generator should be deleted at the end of the run.
     */
    private static final boolean DELETE_LOAD_GENERATOR = true;

    /**
     * Delay before retrying API call.
     */
    public static final int RETRY_DELAY_MILLIS = 100;



    /**
     *  Main method to run the auto-scaling Task2.
     * @param args No args required
     */
    public static void main(final String[] args) {
        AWSCredentialsProvider credentialsProvider =
                new DefaultAWSCredentialsProviderChain();

        // Create an Amazon Ec2 Client
        final AmazonEC2 ec2 = AmazonEC2ClientBuilder
                .standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.US_EAST_1)
                .build();

        // Create an Amazon auto scaling client
        final AmazonAutoScaling aas = AmazonAutoScalingClientBuilder
                .standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.US_EAST_1)
                .build();

        // Create an ELB client
        final AmazonElasticLoadBalancing elb
                = AmazonElasticLoadBalancingClientBuilder
                .standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.US_EAST_1)
                .build();

        // Create a cloudwatch client
        final AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder
                .standard()
                .withCredentials(credentialsProvider)
                .withRegion(Regions.US_EAST_1)
                .build();

        runAutoScalingTask(ec2, aas, elb, cloudWatch);

    }

    /**
     * Run the autoscaling task.
     * @param ec2 EC2
     * @param aas AAS
     * @param elb ELB
     * @param cloudWatch Cloud watch Interface
     */
    private static void runAutoScalingTask(
            AmazonEC2 ec2,
            AmazonAutoScaling aas,
            AmazonElasticLoadBalancing elb,
            AmazonCloudWatch cloudWatch) {
        // BIG PICTURE TODO: Programmatically provision autoscaling resources
        //   - Create security groups for Load Generator and ASG, ELB
        //   - Provision a Load Generator
        //   - Generate a Launch Configuration
        //   - Create a Target Group
        //   - Provision a Load Balancer
        //   - Associate Target Group with Load Balancer 
        //   - Create an Autoscaling Group 
        //   - Initialize Warmup Test
        //   - Initialize Autoscaling Test
        //   - Terminate Resources

        ResourceConfig resourceConfig = initializeResources(ec2, elb, aas, cloudWatch);
        resourceConfig = initializeTestResources(ec2, resourceConfig);

        executeTest(resourceConfig);

        destroy(aas, ec2, elb, cloudWatch, resourceConfig);
    }

    /**
     * Intialize Auto-scaling Task Resources.
     * @param ec2 EC2 client
     * @param elb ELB Client
     * @param aas AAS Client
     * @param cloudWatch Cloud Watch Client
     * @return Load Balancer instance
     */
    private static ResourceConfig initializeResources(final AmazonEC2 ec2,
                                        final AmazonElasticLoadBalancing elb,
                                        final AmazonAutoScaling aas,
                                        final AmazonCloudWatch cloudWatch) {

        //TODO: Create a target group and a load balancer instance 
        //      check Elb.java for more information
        //TODO: Create an auto scaling group. 
        //      check Aas.java for more information

        String targetGroupArn = "";
        String loadBalancerDNS = "";
        String loadBalancerArn = "";

        ResourceConfig resourceConfig = new ResourceConfig();
        resourceConfig.setTargetGroupArn(targetGroupArn);
        resourceConfig.setLoadBalancerArn(loadBalancerArn);
        resourceConfig.setLoadBalancerDns(loadBalancerDNS);
        return resourceConfig;
    }

    /**
     * Create a load Generator and initialize test.
     * @param ec2 EC2 client
     * @param config Resource configuration
     * @return config Resource configuration
     */
    public static ResourceConfig initializeTestResources(final AmazonEC2 ec2,
                                                                     final ResourceConfig config) {
        Instance loadGenerator = null;

        //TODO: Create a Load Generator instance

        config.setLoadGeneratorDns(loadGenerator.getPublicDnsName());
        config.setLoadGeneratorID(loadGenerator.getInstanceId());
        return config;
    }

    /**
     * Execute auto scaling test.
     * @param resourceConfig Resource configuration
     */
    public static void executeTest(ResourceConfig resourceConfig) {
        boolean submissionPasswordUpdated = false;

        while (!submissionPasswordUpdated) {
            try {
                Api.authenticate(resourceConfig.getLoadGeneratorDns());
                submissionPasswordUpdated = true;
            } catch (Exception e) {
                try {
                    Thread.sleep(100); //small sleep > 1s
                } catch (InterruptedException e1) {
                    e1.printStackTrace();
                }
            }
        }


        //Submit ELB DNS to Load Generator for Warmup test 
        executeWarmUp(resourceConfig);

        //Submit ELB DNS to Load Generator for Auto-scaling test
        boolean testStarted = false;
        String response = "";
        while (!testStarted) {
            try {
                response
                = Api.initializeTest(resourceConfig.getLoadGeneratorDns(),
                        resourceConfig.getLoadBalancerDns());
                testStarted = true;

            } catch (Exception e) {
                //Ignore errors
            }
        }

        //Test started
        waitForTestEnd(resourceConfig, response);
    }


    /**
     * Execute warm-up test using API.
     * @param resourceConfig Resource Configuration
     */
    private static void executeWarmUp(ResourceConfig resourceConfig) {
        boolean warmupStarted = false;
        String warmupResponse = "";
        while (!warmupStarted) {
            try {
                warmupResponse = Api.initializeWarmup(resourceConfig.getLoadGeneratorDns(),
                        resourceConfig.getLoadBalancerDns());
                warmupStarted = true;
            } catch (Exception e) {
                try {
                    Thread.sleep(RETRY_DELAY_MILLIS);
                } catch (InterruptedException e1) {
                    e1.printStackTrace();
                }
            }
        }

        //Test started
        waitForTestEnd(resourceConfig, warmupResponse);
    }


    /**
     * Wait For Test Execution to be complete.
     * @param resourceConfig Resource Configuration
     * @param response Response from Test Initialization.
     */
    private static void waitForTestEnd(ResourceConfig resourceConfig, String response) {
        try {
            Ini ini = Api.getIniUpdate(resourceConfig.getLoadGeneratorDns(),
                    Api.getTestId(response));
            while (!ini.containsKey("Test finished")) {
                ini = Api.getIniUpdate(resourceConfig.getLoadGeneratorDns(),
                        Api.getTestId(response));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Destroy all resources created for the task.
     * @param aas AmazonAutoScaling
     * @param ec2 AmazonEC2
     * @param elb AmazonElasticLoadBalancing
     * @param cloudWatch AmazonCloudWatch
     * @param resourceConfig Resource Configuration
     */
    public static void destroy(final AmazonAutoScaling aas,
                               final AmazonEC2 ec2,
                               final AmazonElasticLoadBalancing elb,
                               final AmazonCloudWatch cloudWatch,
                               final ResourceConfig resourceConfig) {

        //TODO: Terminate All Resources



    }

}
