package edu.cmu.cs.cloud;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Data;

/**
 * The domain class that is mapped to the "businesses" table.
 *
 * A domain class is used to map the data from the persistent storage (e.g. DB)
 * to in-memory objects.
 *
 * The Lombok {@link Data} annotation will generate a set of methods, e.g.
 * getters for all fields,
 * setters for all non-final fields,
 * toString() as well as a constructor.
 *
 * You only need to update this class by adding the fields that are missing.
 * The Lombok {@link Data} annotation will create the new getters, setters, and
 * update the implementation of {@link #toString()}.
 *
 * The object(s) will be serialized to JSON object(s) in {@link YelpApp}.
 * The order of the fields does not matter.
 */
@Data
@Entity
@Table(name = "businesses")
public class Business {

    /**
     * `address` varchar(140) not null.
     */
    @Column
    private String address;
    /**
     * `business_id` varchar(22) not null.
     * primary key (business_id)
     */
    @Column
    @Id
    private String business_id;
    /**
     * `city` varchar(140) default null.
     */
    @Column
    private String city;
    /**
     * `hours` LONGTEXT default null.
     */
    @Column
    private String hours;
    /**
     * `latitude` varchar(12) not null.
     */
    @Column
    private String latitude;
    /**
     * `longitude` varchar(12) not null.
     */
    @Column
    private String longitude;
    /**
     * `name` varchar(140) not null.
     */
    @Column
    private String name;
    /**
     * `postal_code` varchar(10) not null.
     */
    @Column
    private String postal_code;
    /**
     * `review_count` int(10) default 0 not null.
     */
    @Column
    private int review_count;
    /**
     * `stars` float(2,1) default 0.0 not null.
     */
    @Column
    private float stars;
    /**
     * `state` varchar(2) default null.
     */
    @Column
    private String state;
    /**
     * `neighborhood` varchar(140) default null.
     */
    @Column
    private String neighborhood;
    /**
     * `attributes` LONGTEXT default null.
     */
    @Column
    private String attributes;

    /**
     * `categories` LONGTEXT default null.
     */
    @Column
    private String categories;
    /**
     * `open` tinyint(1) not null.
     */
    @Column
    private boolean open;
}
