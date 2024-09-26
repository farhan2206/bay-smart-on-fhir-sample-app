import pydicom

dicom_file_path = r"C:\Users\This PC\Downloads\dicom files\report.dcm"
# or dicom_file_path = "C:/Users/This PC/Downloads/dicom files/report.dcm"
print("dicom :: "+dicom_file_path)
dataset = pydicom.dcmread(dicom_file_path)
patient_name = dataset.PatientName
print("Patient Name:", patient_name)
