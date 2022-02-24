package edu.cmu.cs.sample;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Data;
import lombok.NonNull;

@Data
@Entity
@Table(name = "course")
public class Course {
    @Id
    @Column
    @NonNull
    String courseId;

    @Column
    @NonNull
    String name;
}
