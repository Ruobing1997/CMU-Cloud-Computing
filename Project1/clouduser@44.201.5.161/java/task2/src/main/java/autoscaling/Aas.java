package autoscaling;

import com.amazonaws.services.autoscaling.AmazonAutoScaling;
import com.amazonaws.services.autoscaling.model.Tag;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;

import java.util.Arrays;
import java.util.List;

import static autoscaling.AutoScale.PROJECT_VALUE;
import static autoscaling.AutoScale.configuration;


/**
 * Amazon AutoScaling resource class.
 */
public final class Aas {
    /**
     * Max size of AGS.
     */
    private static final Integer MAX_SIZE_AGS
            = configuration.getInt("asg_max_size");

    /**
     * Health Check grace period.
     */
    private static final Integer HEALTH_CHECK_GRACE
            = configuration.getInt("health_check_grace_period");
    /**
     * Cool down period Scale In.
     */
    private static final Integer COOLDOWN_PERIOD_SCALEIN
            = configuration.getInt("cool_down_period_scale_in");

    /**
     * Cool down period Scale Out.
     */
    private static final Integer COOLDOWN_PERIOD_SCALEOUT
            = configuration.getInt("cool_down_period_scale_out");

    /**
     * Number of instances to scale out by.
     */
    private static final int SCALING_OUT_ADJUSTMENT
            = configuration.getInt("scale_out_adjustment");
    /**
     * Number of instances to scale in by.
     */
    private static final int SCALING_IN_ADJUSTMENT
            = configuration.getInt("scale_in_adjustment");

    /**
     * ASG Cool down period in seconds.
     */
    private static final Integer COOLDOWN_PERIOD_ASG
            = configuration.getInt("asg_default_cool_down_period");

    /**
     * Unused constructor.
     */
    private Aas() {
    }

    /**
     * AAS Tags List.
     */
    private static final List<Tag> AAS_TAGS_LIST = Arrays.asList(
            new Tag().withKey("Project").withValue(PROJECT_VALUE));

    /**
     * Create launch configuration.
     *
     * @param aas AAS client
     */
    static void createLaunchConfiguration(final AmazonAutoScaling aas) {
        //TODO: Implement this method 
    }

    /**
     * Create auto scaling group.
     * Create and attach Cloud Watch Policies.
     *
     * @param aas            AAS Client
     * @param cloudWatch     CloudWatch client
     * @param targetGroupArn target group arn
     */
    public static void createAutoScalingGroup(final AmazonAutoScaling aas,
                                              final AmazonCloudWatch cloudWatch,
                                              final String targetGroupArn) {
        //TODO: Implement this method

    }

    /**
     * Terminate auto scaling group.
     *
     * @param aas AAS client
     */
    public static void terminateAutoScalingGroup(final AmazonAutoScaling aas) {
        //TODO: Implement this method
    }

    /**
     * Delete launch configuration.
     *
     * @param aas AAS client
     */
    public static void deleteLaunchConfiguration(final AmazonAutoScaling aas) {
        //TODO: Implement this method
    }
}
