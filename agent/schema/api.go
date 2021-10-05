package schema

type System struct {
	Platform		   string `json:"platform,omitempty"`
	Architecture 	   string `json:"system_architecture,omitempty"`
	Type 		 	   string `json:"system_type,omitempty"`
	NumberOfProcessors uint32 `json:"number_of_processors,omitempty"`
}

type ResponseObject struct {
	MinioObjectKey string `json:"minio_object_key,omitempty"`
	Sha256         string `json:"sha256,omitempty"`
	FileType       string `json:"file_type"`
}

type StatusChanger struct {
	MinioObjectKey string `json:"minio_object_key,omitempty"`
	Sha256         string `json:"sha256,omitempty"`
	FileType       string `json:"file_type"`
	Status 		   int `json:"status,omitempty"`
}

type RequestJob struct {
	MinioObjectKey string `json:"minio_object_key,omitempty"`
	Sha256         string `json:"sha256,omitempty"`
	FileType       string `json:"file_type"`
	JobStartStatus bool   `json:"job_start_status"`
}

type Response struct {
	Sha256      string `json:"sha256,omitempty"`
	FileName    string `json:"filename,omitempty"`
	FileSize    int64  `json:"filesize,omitempty"`
	System 		System `json:"system,omitempty"`
	Message     string `json:"message,omitempty"`
	Description string `json:"description,omitempty"`
}

type Result struct {
	Status string `json:"status,omitempty"`
}
type ResponsePid struct {
	MalwareName string `json:"malware_name"`
	Pid          int32 `json:"pid"`
}