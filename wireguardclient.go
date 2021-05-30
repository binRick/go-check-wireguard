package main

func (w *WireguardClient) GetLatestStageResultName() string {
	qty := len(w.CheckStageResults)
	if qty < 1 {
		return `None`
	}
	csr := w.CheckStageResults[qty-1]
	return csr.Name
}
