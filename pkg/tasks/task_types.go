// task_types.go

package tasks

// TaskType 定义了任务类型
type TaskType string

const (
	TaskTypeSubfinder TaskType = "subfinder"
	TaskTypeNmap      TaskType = "nmap"
	TaskTypeFfuf      TaskType = "ffuf"
	TaskTypeFscan     TaskType = "fscan"
	TaskTypeGogo      TaskType = "gogo"
	// 在这里添加其他任务类型
	// TaskTypeExample TaskType = "example"
)
