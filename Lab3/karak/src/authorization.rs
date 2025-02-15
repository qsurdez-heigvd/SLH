//! Wrapper d'appel à Casbin pour la vérification statique
//! des conventions objet-action

use casbin::CoreApi;
use log::{error, info};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

use crate::models::{MedicalReport, Role, UserData};

const CONFIG: &str = "access_control/model.conf";
const POLICY: &str = "access_control/policy.csv";

/// Un enforcer Casbin
pub struct Enforcer(casbin::Enforcer);

type CasbinResult = Result<(), AccessDenied>;

/// Une erreur sans détails en cas d'accès refusé
#[derive(Debug, Error)]
#[error("Accès refusé.")]
pub struct AccessDenied;

/// Un contexte contenant une référence à un enforcer et à un sujet.
pub struct Context<'ctx> {
    enforcer: &'ctx Enforcer,
    subject: &'ctx UserData,
}

impl Enforcer {
    pub fn load() -> Result<Self, casbin::Error> {
        let mut enforcer = futures::executor::block_on(casbin::Enforcer::new(CONFIG, POLICY))?;
        futures::executor::block_on(enforcer.load_policy())?;
        Ok(Enforcer(enforcer))
    }

    pub fn with_subject<'ctx>(&'ctx self, subject: &'ctx UserData) -> Context<'ctx> {
        Context {
            enforcer: self,
            subject,
        }
    }
}

impl Context<'_> {
    fn enforce<O>(&self, object: O, action: &str) -> CasbinResult
    where
        O: Serialize + std::fmt::Debug + std::hash::Hash,
    {
        let subject = self.subject;

        info!(
            "Enforcing {}",
            json!({ "sub": subject, "obj": &object, "act": action })
        );

        match self.enforcer.0.enforce((subject, &object, action)) {
            Err(e) => {
                error!("Casbin error: {e:?}");
                Err(AccessDenied)
            }
            Ok(r) => {
                info!("Granted: {r}");
                if r {
                    Ok(())
                } else {
                    Err(AccessDenied)
                }
            }
        }
    }

    pub fn read_data(&self, patient: &UserData) -> CasbinResult {
        self.enforce(patient, "read-data")
    }

    pub fn update_data(&self, target: &UserData) -> CasbinResult {
        self.enforce(target, "update-data")
    }

    pub fn delete_data(&self, target: &UserData) -> CasbinResult {
        self.enforce(target, "delete-data")
    }

    pub fn add_report(&self, patient: &UserData, report: &MedicalReport) -> CasbinResult {
        self.enforce(
            json!({ "patient": patient, "report": report }),
            "add-report",
        )
    }

    pub fn read_report(&self, report: &MedicalReport, patient: &UserData) -> CasbinResult {
        self.enforce(json!({"report": report, "patient": patient}), "read-report")
    }

    pub fn update_report(&self, report: &MedicalReport) -> CasbinResult {
        self.enforce(report, "update-report")
    }

    pub fn update_role(&self, target: &UserData, role: Role) -> CasbinResult {
        self.enforce(json!({ "target": target, "role": role }), "update-role")
    }

    pub fn add_doctor(&self, target: &UserData, doctor: &UserData) -> CasbinResult {
        self.enforce(json!({"patient": target, "doctor": doctor}), "add-doctor")
    }

    pub fn remove_doctor(&self, target: &UserData, doctor: &UserData) -> CasbinResult {
        self.enforce(json!({"patient": target, "doctor": doctor}), "remove-doctor")
    }
}


#[cfg(test)]
mod test {
    use std::collections::BTreeSet;
    use crate::models::*;
    use crate::utils::input_validation::{AVSNumber, Username};
    use crate::utils::password_utils::{hash};
    use super::*;

    /// Creates an enforcer to use within the test
    fn set_enforcer() -> Enforcer {
        Enforcer::load().expect("Error in loading Enforcer")
    }

    /// Creates a test user with the given role and username
    fn create_test_user(role: Role, username: &str) -> UserData {
        UserData {
            id: UserID::new(),
            role,
            username: Username::try_from(username.to_string()).unwrap(),
            password: hash("password123"),
            medical_folder: None,
        }
    }

    /// Creates a test user with a medical folder
    fn create_test_patient(username: &str, doctor: UserID) -> UserData {
        let mut user = create_test_user(Role::Patient, username);
        user.medical_folder = Some(MedicalFolder {
            personal_data: PersonalData {
                avs_number: AVSNumber::try_from("756.1234.5678.97".to_string()).unwrap(),
                blood_type: BloodType::A,
            },
            doctors: BTreeSet::from_iter([doctor]),
        });
        user
    }

    /// Creates a test doctor
    fn create_test_doctor(username: &str) -> UserData {
        create_test_user(Role::Doctor, username)
    }

    /// Creates a test admin
    fn create_test_admin(username: &str) -> UserData {
        create_test_user(Role::Admin, username)
    }

    /// Creates a test medical report
    fn create_test_report(author: UserID, patient: UserID) -> MedicalReport {
        MedicalReport {
            id: ReportID::new(),
            title: "Test Report".to_string(),
            author,
            patient,
            content: "Test content".to_string(),
        }
    }

    #[test]
    fn test_admin_permissions() {
        let enforcer = set_enforcer();
        let admin = create_test_admin("admin");
        let doctor = create_test_doctor("doctor");
        let patient = create_test_patient("patient", doctor.id);
        let report = create_test_report(doctor.id, patient.id);
        let context = enforcer.with_subject(&admin);

        // Test 1: Admin read data permission
        let read_data_result = context.read_data(&patient);
        assert!(
            read_data_result.is_ok(),
            "Admin should be able to read any patient's data (Casbin rule: p, read-data, r.sub.role == \"Admin\"), but got error: {:?}",
            read_data_result.err()
        );

        // Test 2: Admin update data permission
        let update_data_result = context.update_data(&patient);
        assert!(
            update_data_result.is_ok(),
            "Admin should be able to update any patient's data (Casbin rule: p, update-data, r.sub.role == \"Admin\"), but got error: {:?}",
            update_data_result.err()
        );

        // Test 3: Admin delete data permission
        let delete_data_result = context.delete_data(&patient);
        assert!(
            delete_data_result.is_ok(),
            "Admin should be able to delete any patient's data (Casbin rule: p, delete-data, r.sub.role == \"Admin\"), but got error: {:?}",
            delete_data_result.err()
        );

        // Test 4: Admin doctor management permissions
        let new_doctor = create_test_doctor("new_doctor");

        let add_doctor_result = context.add_doctor(&patient, &new_doctor);
        assert!(
            add_doctor_result.is_ok(),
            "Admin should be able to add doctors to any patient (Casbin rule: p, add-doctor, r.sub.role == \"Admin\"), but got error: {:?}",
            add_doctor_result.err()
        );

        let remove_doctor_result = context.remove_doctor(&patient, &new_doctor);
        assert!(
            remove_doctor_result.is_ok(),
            "Admin should be able to remove doctors from any patient (Casbin rule: p, remove-doctor, r.sub.role == \"Admin\"), but got error: {:?}",
            remove_doctor_result.err()
        );

        // Test 5: Admin report management permissions
        let add_report_result = context.add_report(&patient, &report);
        assert!(
            add_report_result.is_ok(),
            "Admin should be able to add reports for any patient (Casbin rule: p, add-report, r.sub.role == \"Admin\"), but got error: {:?}",
            add_report_result.err()
        );

        let update_report_result = context.update_report(&report);
        assert!(
            update_report_result.is_ok(),
            "Admin should be able to update any report (Casbin rule: p, update-report, r.sub.role == \"Admin\"), but got error: {:?}",
            update_report_result.err()
        );

        let read_report_result = context.read_report(&report, &patient);
        assert!(
            read_report_result.is_ok(),
            "Admin should be able to read any report (Casbin rule: p, read-report, r.sub.role == \
            \"Admin\"), but got error: {:?}",
            read_report_result.err()
        );

        // Test 6: Admin role management permission
        let role_update_result = context.update_role(&patient, Role::Doctor);
        assert!(
            role_update_result.is_ok(),
            "Admin should be able to update any user's role (Casbin rule: p, update-role, r.sub.role == \"Admin\"), but got error: {:?}",
            role_update_result.err()
        );
    }

    #[test]
    fn test_user_self_management() {
        let enforcer = set_enforcer();
        let doctor = create_test_doctor("doctor");
        let patient = create_test_patient("patient", doctor.id);
        let report = create_test_report(doctor.id, patient.id);

        // Patient or doctor
        let context = enforcer.with_subject(&patient);

        // User can read their own data
        let read_data_result = context.read_data(&patient);
        assert!(
            read_data_result.is_ok(),
            "User should be able to read their own data (Casbin rule: p, read-data, r.sub.id \
            == r.obj.id), but got error: {:?}",
            read_data_result.err()
        );

        // User can delete their own data
        let delete_data_result = context.delete_data(&patient);
        assert!(
            delete_data_result.is_ok(),
            "User should be able to delete their own data (Casbin rule: p, delete-data, r.sub.id \
            == r.obj.id), but got error: {:?}",
            delete_data_result.err()
        );

        // User can update their own data
        let update_data_result = context.update_data(&patient);
        assert!(
            update_data_result.is_ok(),
            "User should be able to update their own data (Casbin rule: p, update-data, r.sub.id \
            == r.obj.id), but got error: {:?}",
            update_data_result.err()
        );

        // User can choose their doctor
        let add_doctor_result = context.add_doctor(&patient, &doctor);
        assert!(
            add_doctor_result.is_ok(),
            "User can add their doctor to their medical folder (Casbin rule: p, add-doctor, r.sub\
            .id == r.obj.patient.id && (r.obj.doctor.role == \"Doctor\" || r.obj.doctor.role == \
            \"Admin\"), but got: {:?}",
            add_doctor_result.err()
        );

        // User can remove their doctor
        let remove_doctor_result = context.remove_doctor(&patient, &doctor);
        assert!(
            remove_doctor_result.is_ok(),
            "User can remove their doctor to their medical folder (Casbin rule: p, remove-doctor,\
             r.sub.id == r.obj.patient.id && (r.obj.doctor.role == \"Doctor\" || r.obj.doctor\
             .role == \"Admin\"), but got: {:?}",
            remove_doctor_result.err()
        )
    }

    #[test]
    fn test_patient_without_permission() {
        let enforcer = set_enforcer();
        let doctor = create_test_doctor("doctor");
        let patient = create_test_patient("patient", doctor.id);
        let report = create_test_report(doctor.id, patient.id);
        let context = enforcer.with_subject(&patient);

        // Patient should not be able to manage the reports
        let add_report_result = context.add_report(&patient, &report);
        assert!(
            add_report_result.is_err(),
            "User should not be able to add reports for any patient, but got: {:?}",
            add_report_result.ok()
        );

        let update_report_result = context.update_report(&report);
        assert!(
            update_report_result.is_err(),
            "User should not be able to update any report but got: {:?}",
            update_report_result.ok()
        );

        let read_report_result = context.read_report(&report, &patient);
        assert!(
            read_report_result.is_err(),
            "User should not be able to read any report, but got: {:?}",
            read_report_result.ok()
        );

        // Patient should not be able to update the role of a person
        let role_update_result = context.update_role(&patient, Role::Doctor);
        assert!(
            role_update_result.is_err(),
            "User should not be able to update any user's role, but got: {:?}",
            role_update_result.ok()
        );
    }

    #[test]
    fn test_doctor_permissions() {
        let enforcer = set_enforcer();
        let admin = create_test_admin("admin");
        let doctor = create_test_doctor("doctor");
        let patient = create_test_patient("patient", doctor.id);
        let context = enforcer.with_subject(&doctor);

        // Doctor can see the data from their patient
        let read_data_patient_result = context.read_data(&patient);
        assert!(
            read_data_patient_result.is_ok(),
            "Doctor should be able to see the data from their patient (Casbin rule: p, read-data,\
             r.sub.role == \"Doctor\" && r.obj.patient.medical_folder != () && r.obj.patient\
             .medical_folder.doctors.contains(r.sub.id), but got: {:?}",
            read_data_patient_result.err()
        );

        // Doctor can only see the data from their patient
        let new_doctor = create_test_doctor("newDoc");
        let context_new = enforcer.with_subject(&new_doctor);

        let read_data_not_authorized = context_new.read_data(&patient);
        assert!(
            read_data_not_authorized.is_err(),
            "Doctor should not be able to read data from patient that are not theirs, but got: \
            {:?}",
            read_data_not_authorized.ok()
        );

        // Doctor can add a report for any patient
        let report = create_test_report(new_doctor.id, patient.id);
        let add_report_patient = context_new.add_report(&patient, &report);

        assert!(
            add_report_patient.is_ok(),
            "Doctor should be able to add a report for a patient (Casbin rule: p, add-report, r\
            .sub.role == \"Doctor\" && r.sub.id == r.obj.report.author && r.obj.patient.id == r\
            .obj.report.patient && r.obj.patient.medical_folder != null, but got: {:?}",
            add_report_patient.err()
        );

        // Doctor can modify their report
        let update_report = context_new.update_report(&report);

        assert!(
            update_report.is_ok(),
            "Author of a report should be able to modify it (Casbin rule: p, read-report, r.obj\
            .author == r.sub.id), but got: {:?}",
            update_report.err()
        );

        // Doctor can read their report
        let read_report = context_new.read_report(&report, &patient);

        assert!(
            read_report.is_ok(),
            "Author of a report should be able to read it (Casbin rule: p, read-report, r.obj\
            .author == r.sub.id), but got: {:?}",
            read_report.err()
        );

        // Doctor can read all the reports of their patient
        let read_report_patient = context.read_report(&report, &patient);

        assert!(
            read_report_patient.is_ok(),
            "Doctor should be able to read report of their patient (Casbin rule: p, read-report, \
            r.sub.role == \"Doctor\" && r.obj.medical_folder != () && r.obj.medical_folder\
            .doctors.contains(r.sub.id), but got: {:?}",
            read_report_patient.err()
        );
    }
}
