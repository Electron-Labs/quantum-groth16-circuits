package verifier

type Proof struct {
	A        []string   `json:"pi_a"`
	B        [][]string `json:"pi_b"`
	C        []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
	Curve    string     `json:"curve"`
}

type VK struct {
	Protocol  string       `json:"protocol"`
	Curve     string       `json:"curve"`
	NPublic   uint8        `json:"nPublic"`
	Alpha     []string     `json:"vk_alpha_1"`
	Beta      [][]string   `json:"vk_beta_2"`
	Gamma     [][]string   `json:"vk_gamma_2"`
	Delta     [][]string   `json:"vk_delta_2"`
	Alphabeta [][][]string `json:"vk_alphabeta_12"`
	IC        [][]string
}
