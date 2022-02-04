package autoscaling;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.ini4j.Ini;

import utilities.HttpRequest;

/**
 * Server API Class.
 */
public final class Api {
    /**
     * Submission Password.
     */
    private static final String SUBMISSION_PASSWORD
            = System.getenv("SUBMISSION_PASSWORD");
    /**
     * Submission Username.
     */
    private static final String SUBMISSION_USERNAME
            = System.getenv("SUBMISSION_USERNAME");

    /**
     * Unused Constructor.
     */
    private Api() {
    }

    /**
     * Supply LG with submission credentials.
     *
     * @param loadGeneratorDNS DNS Name of load generator
     */
    public static void authenticate(final String loadGeneratorDNS) {
        boolean loadGeneratorSuccess = false;
        while (!loadGeneratorSuccess) {
            try {
                String response = HttpRequest.sendGet("http://"
                        + loadGeneratorDNS + "/password?passwd="
                        + SUBMISSION_PASSWORD
                        + "&username="
                        + SUBMISSION_USERNAME);
                System.out.println(response);
                loadGeneratorSuccess = true;
            } catch (Exception e) {
                //ignore errors
            }
        }
    }

    /**
     * Add an ELB.
     * @param loadGeneratorDNS LG DNS name
     * @param loadBalancerDNS ELB DNS name
     * @return return server response.
     */
    public static String initializeTest(final String loadGeneratorDNS,
                                              final String loadBalancerDNS) {
        String response = "";
        boolean launchWebServiceSuccess = false;
        while (!launchWebServiceSuccess) {
            try {
                response = HttpRequest.sendGet(
                        "http://" + loadGeneratorDNS
                                + "/autoscaling?dns=" + loadBalancerDNS);
                System.out.println(response);
                launchWebServiceSuccess = true;
            } catch (Exception e) {
                //ignore errors
            }
        }
        return response;
    }

    /**
     * Warm up an ELB.
     * @param loadGeneratorDNS LG DNS name
     * @param loadBalancerDNS ELB DNS Name
     * @return return response response
     */
    public static String initializeWarmup(final String loadGeneratorDNS,
                                   final String loadBalancerDNS) {
        String response = "";
        boolean launchTestSuccess = false;
        while (!launchTestSuccess) {
            try {
                response = HttpRequest.sendGet(
                        "http://" + loadGeneratorDNS
                                + "/warmup?dns=" + loadBalancerDNS);
                System.out.println(response);
                launchTestSuccess = true;
            } catch (Exception e) {
                //ignore errors
            }
        }
        return response;
    }

    /**
     * Get the latest version of the log.
     *
     * @param loadGeneratorDNS DNS Name of load generator
     * @param testId           TestID String
     * @return INI Object
     * @throws IOException on network failure
     */
    public static Ini getIniUpdate(final String loadGeneratorDNS,
                                   final String testId)
            throws IOException {
        String response = HttpRequest.sendGet("http://"
                + loadGeneratorDNS + "/log?name=test." + testId + ".log");
        File log = new File(testId + ".log");
        FileUtils.writeStringToFile(log, response, Charset.defaultCharset());
        Ini ini = new Ini(log);
        return ini;
    }

    /**
     * Get ID of test.
     *
     * @param response Response containing LoadGenerator output
     * @return TestID string
     */
    public static String getTestId(final String response) {
        Pattern pattern = Pattern.compile("test\\.([0-9]*)\\.log");
        Matcher matcher = pattern.matcher(response);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
}
