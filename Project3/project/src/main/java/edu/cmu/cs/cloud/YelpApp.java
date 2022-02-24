package edu.cmu.cs.cloud;

import java.io.IOException;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.codehaus.jackson.map.ObjectMapper;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.query.Query;
import org.hibernate.service.ServiceRegistry;

/**
 * To develop an application with Hibernate, two sets of configurations are
 * needed.
 * 1. the database connection configuration
 * 2. the mapping between domain model classes and database tables
 *
 * Usage:
 * mvn clean package && java -cp target/database_tasks.jar edu.cmu.cs.cloud.YelpApp
 *
 * You are NOT allowed to edit this class, or your submission will be rejected.
 */
public class YelpApp {

    /**
     * Logger.
     */
    private static final Logger LOGGER = Logger.getRootLogger();

    /**
     * Username and password.
     */
    private static final String DB_USER = System.getProperty("user.name");
    private static final String DB_PWD = System.getenv("MYSQL_PWD");

    /**
     * SessionFactory is an immutable thread-safe cache of compiled mappings for
     * a database.
     *
     * @return SessionFactory
     */
    private static SessionFactory buildSessionFactory() {
        try {
            Configuration configuration = new Configuration();
            /*
             * Read the database connection configuration from
             * "src/main/resources/hibernate.properties".
             */
            Properties props = new Properties();
            props.load(YelpApp.class.getResourceAsStream(
                    "/hibernate.properties"));

            if (props.getOrDefault("hibernate.connection.driver_class", "")
                    .equals("com.mysql.jdbc.Driver")) {
                props.put("hibernate.connection.username", DB_USER);
                props.put("hibernate.connection.password", DB_PWD);
            }

            configuration.setProperties(props);
            // set the mapping between domain model classes and database tables
            configuration.addAnnotatedClass(Business.class);

            ServiceRegistry serviceRegistry = new StandardServiceRegistryBuilder()
                    .applySettings(configuration.getProperties()).build();
            return configuration.buildSessionFactory(serviceRegistry);
        } catch (Throwable ex) {
            throw new ExceptionInInitializerError(ex);
        }
    }

    /**
     * Main entry.
     *
     * Get the Pittsburgh business with the most reviews in the database as
     * an object of the {@link Business} class and print the string
     * representation of the object using {@link Business#toString()}.
     *
     * You are NOT allowed to edit the main entry method.
     *
     * @param args The arguments for main method.
     */
    public static void main(final String[] args) {
        LOGGER.setLevel(Level.OFF);
        Session session = null;
        SessionFactory sessionFactory = null;
        try {
            sessionFactory = buildSessionFactory();
            session = sessionFactory.getCurrentSession();
            session.beginTransaction();

            /*
             * Similar to the SQL query:
             * SELECT * FROM Business WHERE city = 'Pittsburgh' ORDER BY review_count DESC LIMIT 1;
             */
            Query query = session.createQuery(
                    "from Business where city = 'Pittsburgh' order by review_count desc");
            query.setMaxResults(1);

            ObjectMapper objectMapper = new ObjectMapper();
            @SuppressWarnings("unchecked")
            List<Business> businesses = query.list();
            for (Business business : businesses) {
                try {
                    // serialize the object into JSON and print
                    System.out.println(objectMapper.writeValueAsString(business));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            session.getTransaction().commit();
            sessionFactory.close();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (session != null && session.isOpen()) {
                session.close();
            }
            if (sessionFactory != null && sessionFactory.isOpen()) {
                sessionFactory.close();
            }
        }
    }
}
