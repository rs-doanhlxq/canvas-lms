Grading
==============

<h2 id="grade_change">grade_change</h2>

**Definition:** The event is emitted anytime when a submission is graded. These can happen as the result of a teacher changing a grade in the gradebook or speedgrader, a quiz being automatically scored, or changing an assignment's points possible or grade type. In the case of a quiz being scored, the `grade_change` event will be emitted as the result of a student turning in a quiz, and the `user_id` in the message attributes will be the student's user ID.

**Trigger:** Triggered anytime a grade is created or modified.


### Event Body Schema

| Field | Description |
|-|-|
| **data[0].group.extensions["com.instructure.canvas"].context_type** | Canvas context type where the action took place e.g context_type = Course. |
| **data[0].group.extensions["com.instructure.canvas"].entity_id** | Canvas context ID |
| **data[0].object.extensions["com.instructure.canvas"].entity_id** | Canvas global ID of the object affected by the event |
| **data[0].object.extensions["com.instructure.canvas"].grade** | The new submission grade |
| **data[0].object.type** | GradeEvent |





### Payload Example:

```json
{
  "sensor": "http://oxana.instructure.com/",
  "sendTime": "2019-11-16T02:09:06.543Z",
  "dataVersion": "http://purl.imsglobal.org/ctx/caliper/v1p1",
  "data": [
    {
      "@context": "http://purl.imsglobal.org/ctx/caliper/v1p1",
      "id": "urn:uuid:319f0132-0584-4efd-9489-4959b7101731",
      "type": "GradeEvent",
      "actor": {
        "id": "urn:instructure:canvas:user:21070000000000987",
        "type": "Person"
      },
      "action": "Graded",
      "object": {
        "id": "urn:instructure:canvas:submission:21070000000011086",
        "type": "Attempt",
        "extensions": {
          "com.instructure.canvas": {
            "grade": "5",
            "entity_id": "21070000000011086"
          }
        },
        "assignee": {
          "id": "urn:instructure:canvas:user:21070000000000048",
          "type": "Person",
          "extensions": {
            "com.instructure.canvas": {
              "sis_id": "ABC.123"
            }
          }
        },
        "assignable": {
          "id": "urn:instructure:canvas:assignment:21070000000000355",
          "type": "AssignableDigitalResource"
        }
      },
      "eventTime": "2019-11-01T19:11:05.222Z",
      "generated": {
        "id": "urn:instructure:canvas:submission:21070000000011086",
        "type": "Score",
        "extensions": {
          "com.instructure.canvas": {
            "grade": "5",
            "entity_id": "21070000000011086"
          }
        },
        "attempt": {
          "id": "urn:instructure:canvas:submission:21070000000011086",
          "type": "Attempt",
          "extensions": {
            "com.instructure.canvas": {
              "grade": "5"
            }
          },
          "assignee": {
            "id": "urn:instructure:canvas:user:21070000000000048",
            "type": "Person",
            "extensions": {
              "com.instructure.canvas": {
                "sis_id": "ABC.123"
              }
            }
          },
          "assignable": {
            "id": "urn:instructure:canvas:assignment:21070000000000355",
            "type": "AssignableDigitalResource"
          }
        },
        "maxScore": 1,
        "scoreGiven": 5,
        "scoredBy": "urn:instructure:canvas:user:21070000000000987"
      },
      "referrer": "https://oxana.instructure.com/courses/565/gradebook",
      "edApp": {
        "id": "http://oxana.instructure.com/",
        "type": "SoftwareApplication"
      },
      "group": {
        "id": "urn:instructure:canvas:course:21070000000000565",
        "type": "CourseOffering",
        "extensions": {
          "com.instructure.canvas": {
            "context_type": "Course",
            "entity_id": "21070000000000565"
          }
        }
      },
      "membership": {
        "id": "urn:instructure:canvas:course:21070000000000565:Instructor:21070000000000987",
        "type": "Membership",
        "member": {
          "id": "urn:instructure:canvas:user:21070000000000987",
          "type": "Person"
        },
        "organization": {
          "id": "urn:instructure:canvas:course:21070000000000565",
          "type": "CourseOffering"
        },
        "roles": [
          "Instructor"
        ]
      },
      "session": {
        "id": "urn:instructure:canvas:session:ef686f8ed684abf78cbfa1f6a58112b5",
        "type": "Session"
      },
      "extensions": {
        "com.instructure.canvas": {
          "hostname": "oxana.instructure.com",
          "request_id": "1dd9dc6f-2fb0-4c19-a6c5-7ee1bf3ed295",
          "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36",
          "client_ip": "93.184.216.34",
          "request_url": "https://oxana.instructure.com/api/v1/courses/565/assignments/355/submissions/48?include%5B%5D=visibility",
          "version": "1.0.0"
        }
      }
    }
  ]
}
```




