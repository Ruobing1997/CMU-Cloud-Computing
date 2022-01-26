package autoscaling;


import com.amazonaws.services.cloudwatch.AmazonCloudWatch;

import static autoscaling.AutoScale.configuration;

/**
 * CloudWatch resources.
 */
public final class Cloudwatch {

    /**
     * Sixty seconds.
     */
    private static final Integer ALARM_PERIOD
            = configuration.getInt("alarm_period");
    /**
     * CPU Lower Threshold.
     */
    private static final Double CPU_LOWER_THRESHOLD
            = configuration.getDouble("cpu_lower_threshold");
    /**
     * CPU Upper Threshold.
     */
    private static final Double CPU_UPPER_THRESHOLD
            = configuration.getDouble("cpu_upper_threshold");
    /**
     * Alarm Evaluation Period out.
     */
    public static final int ALARM_EVALUATION_PERIODS_SCALE_OUT
            = configuration.getInt("alarm_evaluation_periods_scale_out");
    /**
     * Alarm Evaluation Period in.
     */
    public static final int ALARM_EVALUATION_PERIODS_SCALE_IN
            = configuration.getInt("alarm_evaluation_periods_scale_in");

    /**
     * Unused constructor.
     */
    private Cloudwatch() {
    }

    /**
     * Create Scale out alarm.
     *
     * @param cloudWatch cloudWatch instance
     * @param policyArn  policy ARN
     */
    public static void createScaleOutAlarm(final AmazonCloudWatch cloudWatch,
                                           final String policyArn) {
         //TODO: Create scale-out alarm policy

    }

    /**
     * Create ScaleIn Alarm.
     *
     * @param cloudWatch cloud watch instance
     * @param policyArn  policy Arn
     */
    public static void createScaleInAlarm(final AmazonCloudWatch cloudWatch,
                                          final String policyArn) {
        //TODO: Create scale-in alarm policy

    }

    /**
     * Delete the two above Alarms.
     *
     * @param cloudWatch cloud watch client
     */
    public static void deleteAlarms(final AmazonCloudWatch cloudWatch) {
         //TODO: Delete all alarm resources
    }
}
