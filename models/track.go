package models

type GetTrackRequest struct {
	Image     string `json:"image",binding:"required"`
	TrackInfo string `json:"trackInfo",bingding:"required"`
}
