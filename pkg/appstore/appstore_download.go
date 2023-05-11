package appstore

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/blacktop/ranger"
	"github.com/majd/ipatool/pkg/http"
	"github.com/majd/ipatool/pkg/util"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"howett.net/plist"
	"io"
	nhttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type DownloadSinfResult struct {
	ID   int64  `plist:"id,omitempty"`
	Data []byte `plist:"sinf,omitempty"`
}

type DownloadItemResult struct {
	HashMD5  string                 `plist:"md5,omitempty"`
	URL      string                 `plist:"URL,omitempty"`
	Sinfs    []DownloadSinfResult   `plist:"sinfs,omitempty"`
	Metadata map[string]interface{} `plist:"metadata,omitempty"`
}

type DownloadResult struct {
	FailureType     string               `plist:"failureType,omitempty"`
	CustomerMessage string               `plist:"customerMessage,omitempty"`
	Items           []DownloadItemResult `plist:"songList,omitempty"`
}

type PackageManifest struct {
	SinfPaths []string `plist:"SinfPaths,omitempty"`
}

type PackageInfo struct {
	BundleExecutable string `plist:"CFBundleExecutable,omitempty"`
}

type DownloadOutput struct {
	DestinationPath string
}

func keylogWriter() io.Writer {

	value, exists := os.LookupEnv("SSLKEYLOGFILE")
	if exists {
		writer, _ := os.OpenFile(value, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0775)
		return writer
	} else {
		return nil
	}
}

func (a *appstore) newPartialZipReader(urlStr string) (*zip.Reader, error) {

	url, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	transport := nhttp.DefaultTransport.(*nhttp.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		KeyLogWriter: keylogWriter(),
	}

	client := nhttp.Client{
		Transport: transport,
	}

	reader, err := ranger.NewReader(&ranger.HTTPRanger{URL: url, Client: &client})

	if err != nil {
		return nil, err
	}

	length, err := reader.Length()

	if err != nil {
		return nil, err
	}

	zr, err := zip.NewReader(reader, length)
	if err != nil {
		return nil, err
	}
	return zr, nil

}

func (a *appstore) ListFiles(bundleID string, acquireLicense bool) ([]string, error) {

	acc, app, guid, err := a.resolveDownload(bundleID, acquireLicense)
	if err != nil {
		return nil, err
	}

	item, err := a.downloadItem(acc, app, guid, acquireLicense, false)

	if err != nil {
		return nil, err
	}

	zip, err := newPartialZipReader(item.URL)
	if err != nil {
		return nil, errors.Wrap(err, ErrDownloadFile.Error())
	}

	var paths []string

	for _, file := range zip.File {
		path := file.Name
		paths = append(paths, path)
	}

	return paths, nil
}

func (a *appstore) DownloadPaths(bundleID string, outputPath string, ipaPaths []string, acquireLicense bool) (DownloadOutput, error) {

	acc, app, guid, err := a.resolveDownload(bundleID, acquireLicense)

	if err != nil {
		return DownloadOutput{}, err
	}

	item, err := a.downloadItem(acc, app, guid, acquireLicense, false)

	if err != nil {
		return DownloadOutput{}, err
	}

	zip, err := a.newPartialZipReader(item.URL)

	if err != nil {
		return DownloadOutput{}, errors.Wrap(err, ErrDownloadFile.Error())
	}

downloadPath:
	for _, ipaPath := range ipaPaths {

		re, err := regexp.Compile("Payload/([^.]*).app/" + regexp.QuoteMeta(ipaPath))

		if err != nil {
			return DownloadOutput{}, err
		}

		for _, file := range zip.File {
			path := file.Name
			if re.Match([]byte(path)) {

				reader, err := zip.Open(file.Name)
				if err != nil {
					return DownloadOutput{}, errors.Wrap(err, ErrDownloadFile.Error())
				}

				defer reader.Close()
				fullPath := filepath.Join(outputPath, file.Name)

				os.MkdirAll(filepath.Dir(fullPath), os.ModePerm)

				a.logger.Log().Str("downloading", file.Name).Send()

				err = a.doDownload(reader, fullPath, int64(file.UncompressedSize64))
				if err != nil {
					return DownloadOutput{}, errors.Wrap(err, ErrDownloadFile.Error())
				}
				continue downloadPath
			}
		}
		a.logger.Log().Str("missing_path", ipaPath).Send()

	}

	return DownloadOutput{}, nil

}

func (a *appstore) resolveDownload(bundleID string, acquireLicense bool) (acc Account, app App, guid string, err error) {
	acc, err = a.account()
	if err != nil {
		err = errors.Wrap(err, ErrGetAccount.Error())
		return
	}

	countryCode, err := a.countryCodeFromStoreFront(acc.StoreFront)
	if err != nil {
		err = errors.Wrap(err, ErrInvalidCountryCode.Error())
		return
	}

	app, err = a.lookup(bundleID, countryCode)
	if err != nil {
		err = errors.Wrap(err, ErrAppLookup.Error())
		return
	}

	macAddr, err := a.machine.MacAddress()
	if err != nil {
		err = errors.Wrap(err, ErrGetMAC.Error())
		return
	}

	guid = strings.ReplaceAll(strings.ToUpper(macAddr), ":", "")
	a.logger.Verbose().Str("mac", macAddr).Str("guid", guid).Send()

	return
}

func (a *appstore) Download(bundleID string, outputPath string, acquireLicense bool) (DownloadOutput, error) {

	acc, app, guid, err := a.resolveDownload(bundleID, acquireLicense)
	if err != nil {
		return DownloadOutput{}, err
	}

	destination, err := a.resolveDestinationPath(app, outputPath)
	if err != nil {
		return DownloadOutput{}, errors.Wrap(err, ErrResolveDestinationPath.Error())
	}

	err = a.download(acc, app, destination, guid, acquireLicense, true)
	if err != nil {
		return DownloadOutput{}, errors.Wrap(err, ErrDownloadFile.Error())
	}

	return DownloadOutput{
		DestinationPath: destination,
	}, nil
}
func (a *appstore) download(acc Account, app App, dst, guid string, acquireLicense, attemptToRenewCredentials bool) error {

	item, err := a.downloadItem(acc, app, guid, acquireLicense, attemptToRenewCredentials)

	err = a.downloadFile(fmt.Sprintf("%s.tmp", dst), item.URL)
	if err != nil {
		return errors.Wrap(err, ErrDownloadFile.Error())
	}

	err = a.applyPatches(*item, acc, fmt.Sprintf("%s.tmp", dst), dst)
	if err != nil {
		return errors.Wrap(err, ErrPatchApp.Error())
	}

	err = a.os.Remove(fmt.Sprintf("%s.tmp", dst))
	if err != nil {
		return errors.Wrap(err, ErrRemoveTempFile.Error())
	}

	return nil
}

func (a *appstore) downloadItem(acc Account, app App, guid string, acquireLicense, attemptToRenewCredentials bool) (*DownloadItemResult, error) {

	req := a.downloadRequest(acc, app, guid)

	res, err := a.downloadClient.Send(req)
	if err != nil {
		return nil, errors.Wrap(err, ErrRequest.Error())
	}

	if res.Data.FailureType == FailureTypePasswordTokenExpired {
		if attemptToRenewCredentials {
			a.logger.Verbose().Msg("retrieving new password token")
			acc, err = a.login(acc.Email, acc.Password, "", guid, 0, true)
			if err != nil {
				return nil, errors.Wrap(err, ErrPasswordTokenExpired.Error())
			}

			return a.downloadItem(acc, app, guid, acquireLicense, false)
		}

		return nil, ErrPasswordTokenExpired
	}

	if res.Data.FailureType == FailureTypeLicenseNotFound && acquireLicense {
		a.logger.Verbose().Msg("attempting to acquire license")
		err = a.purchase(app.BundleID, guid, true)
		if err != nil {
			return nil, errors.Wrap(err, ErrPurchase.Error())
		}

		return a.downloadItem(acc, app, guid, false, attemptToRenewCredentials)
	}

	if res.Data.FailureType == FailureTypeLicenseNotFound {
		return nil, ErrLicenseRequired
	}

	if res.Data.FailureType != "" && res.Data.CustomerMessage != "" {
		a.logger.Verbose().Interface("response", res).Send()
		return nil, errors.New(res.Data.CustomerMessage)
	}

	if res.Data.FailureType != "" {
		a.logger.Verbose().Interface("response", res).Send()
		return nil, ErrGeneric
	}

	if len(res.Data.Items) == 0 {
		a.logger.Verbose().Interface("response", res).Send()
		return nil, ErrInvalidResponse
	}

	item := res.Data.Items[0]

	return &item, nil
}

func (a *appstore) downloadFile(dst, sourceURL string) (err error) {
	req, err := a.httpClient.NewRequest("GET", sourceURL, nil)
	if err != nil {
		return errors.Wrap(err, ErrCreateRequest.Error())
	}

	res, err := a.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, ErrRequest.Error())
	}

	defer func() {
		if closeErr := res.Body.Close(); closeErr != err && err == nil {
			err = closeErr
		}
	}()

	return a.doDownload(res.Body, dst, res.ContentLength)
}

func (a *appstore) doDownload(body io.ReadCloser, dst string, contentLength int64) error {
	file, err := a.os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrap(err, ErrOpenFile.Error())
	}

	defer func() {
		if closeErr := file.Close(); closeErr != err && err == nil {
			err = closeErr
		}
	}()

	sizeMB := float64(contentLength) / (1 << 20)
	a.logger.Verbose().Str("size", fmt.Sprintf("%.2fMB", sizeMB)).Msg("downloading")

	if a.interactive {
		bar := progressbar.NewOptions64(contentLength,
			progressbar.OptionSetDescription("downloading"),
			progressbar.OptionSetWriter(os.Stdout),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(20),
			progressbar.OptionFullWidth(),
			progressbar.OptionThrottle(65*time.Millisecond),
			progressbar.OptionShowCount(),
			progressbar.OptionClearOnFinish(),
			progressbar.OptionSpinnerType(14),
			progressbar.OptionSetRenderBlankState(true),
			progressbar.OptionSetElapsedTime(false),
			progressbar.OptionSetPredictTime(false),
		)

		_, err = io.Copy(io.MultiWriter(file, bar), body)
	} else {
		_, err = io.Copy(file, body)
	}

	if err != nil {
		return errors.Wrap(err, ErrFileWrite.Error())
	}

	return nil
}

func (*appstore) downloadRequest(acc Account, app App, guid string) http.Request {
	host := fmt.Sprintf("%s-%s", PriavteAppStoreAPIDomainPrefixWithoutAuthCode, PrivateAppStoreAPIDomain)
	return http.Request{
		URL:            fmt.Sprintf("https://%s%s?guid=%s", host, PrivateAppStoreAPIPathDownload, guid),
		Method:         http.MethodPOST,
		ResponseFormat: http.ResponseFormatXML,
		Headers: map[string]string{
			"Content-Type": "application/x-apple-plist",
			"iCloud-DSID":  acc.DirectoryServicesID,
			"X-Dsid":       acc.DirectoryServicesID,
		},
		Payload: &http.XMLPayload{
			Content: map[string]interface{}{
				"creditDisplay": "",
				"guid":          guid,
				"salableAdamId": app.ID,
			},
		},
	}
}

func fileName(app App) string {
	return fmt.Sprintf("%s_%d_%s.ipa",
		app.BundleID,
		app.ID,
		app.Version)
}

func (a *appstore) resolveDestinationPath(app App, path string) (string, error) {
	file := fileName(app)

	if path == "" {
		workdir, err := a.os.Getwd()
		if err != nil {
			return "", errors.Wrap(err, ErrGetCurrentDirectory.Error())
		}

		return fmt.Sprintf("%s/%s", workdir, file), nil
	}

	isDir, err := a.isDirectory(path)
	if err != nil {
		return "", errors.Wrap(err, ErrCheckDirectory.Error())
	}

	if isDir {
		return fmt.Sprintf("%s/%s", path, file), nil
	}

	return path, nil
}

func (a *appstore) isDirectory(path string) (bool, error) {
	info, err := a.os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return false, errors.Wrap(err, ErrGetFileMetadata.Error())
	}

	if info == nil {
		return false, nil
	}

	return info.IsDir(), nil
}

func (a *appstore) applyPatches(item DownloadItemResult, acc Account, src, dst string) (err error) {
	dstFile, err := a.os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrap(err, ErrOpenFile.Error())
	}

	srcZip, err := zip.OpenReader(src)
	if err != nil {
		return errors.Wrap(err, ErrOpenZipFile.Error())
	}
	defer func() {
		if closeErr := srcZip.Close(); closeErr != err && err == nil {
			err = closeErr
		}
	}()

	dstZip := zip.NewWriter(dstFile)
	defer func() {
		if closeErr := dstZip.Close(); closeErr != err && err == nil {
			err = closeErr
		}
	}()

	manifestData := new(bytes.Buffer)
	infoData := new(bytes.Buffer)

	appBundle, err := a.replicateZip(srcZip, dstZip, infoData, manifestData)
	if err != nil {
		return errors.Wrap(err, ErrReplicateZip.Error())
	}

	err = a.writeMetadata(item.Metadata, acc, dstZip)
	if err != nil {
		return errors.Wrap(err, ErrWriteMetadataFile.Error())
	}

	if manifestData.Len() > 0 {
		err = a.applySinfPatches(item, dstZip, manifestData.Bytes(), appBundle)
		if err != nil {
			return errors.Wrap(err, ErrApplyPatches.Error())
		}
	} else {
		err = a.applyLegacySinfPatches(item, dstZip, infoData.Bytes(), appBundle)
		if err != nil {
			return errors.Wrap(err, ErrApplyLegacyPatches.Error())
		}
	}

	return nil
}

func (a *appstore) writeMetadata(metadata map[string]interface{}, acc Account, zip *zip.Writer) error {
	metadata["apple-id"] = acc.Email
	metadata["userName"] = acc.Email

	metadataFile, err := zip.Create("iTunesMetadata.plist")
	if err != nil {
		return errors.Wrap(err, ErrCreateMetadataFile.Error())
	}

	data, err := plist.Marshal(metadata, plist.BinaryFormat)
	if err != nil {
		return errors.Wrap(err, ErrEncodeMetadataFile.Error())
	}

	_, err = metadataFile.Write(data)
	if err != nil {
		return errors.Wrap(err, ErrWriteMetadataFile.Error())
	}

	return nil
}

func (a *appstore) replicateZip(src *zip.ReadCloser, dst *zip.Writer, info *bytes.Buffer, manifest *bytes.Buffer) (appBundle string, err error) {
	for _, file := range src.File {
		srcFile, err := file.OpenRaw()
		if err != nil {
			return "", errors.Wrap(err, ErrOpenFile.Error())
		}

		if strings.HasSuffix(file.Name, ".app/SC_Info/Manifest.plist") {
			srcFileD, err := file.Open()
			if err != nil {
				return "", errors.Wrap(err, ErrDecompressManifestFile.Error())
			}

			_, err = io.Copy(manifest, srcFileD)
			if err != nil {
				return "", errors.Wrap(err, ErrGetManifestFile.Error())
			}
		}

		if strings.Contains(file.Name, ".app/Info.plist") {
			srcFileD, err := file.Open()
			if err != nil {
				return "", errors.Wrap(err, ErrDecompressInfoFile.Error())
			}

			if !strings.Contains(file.Name, "/Watch/") {
				appBundle = filepath.Base(strings.TrimSuffix(file.Name, ".app/Info.plist"))
			}

			_, err = io.Copy(info, srcFileD)
			if err != nil {
				return "", errors.Wrap(err, ErrGetInfoFile.Error())
			}
		}

		header := file.FileHeader
		dstFile, err := dst.CreateRaw(&header)
		if err != nil {
			return "", errors.Wrap(err, ErrCreateDestinationFile.Error())
		}

		_, err = io.Copy(dstFile, srcFile)
		if err != nil {
			return "", errors.Wrap(err, ErrFileWrite.Error())
		}
	}

	if appBundle == "" {
		return "", ErrGetBundleName
	}

	return appBundle, nil
}

func (a *appstore) applySinfPatches(item DownloadItemResult, zip *zip.Writer, manifestData []byte, appBundle string) error {
	var manifest PackageManifest
	_, err := plist.Unmarshal(manifestData, &manifest)
	if err != nil {
		return errors.Wrap(err, ErrUnmarshal.Error())
	}

	zipped, err := util.Zip(item.Sinfs, manifest.SinfPaths)
	if err != nil {
		return errors.Wrap(err, ErrZipSinfs.Error())
	}

	for _, pair := range zipped {
		sp := fmt.Sprintf("Payload/%s.app/%s", appBundle, pair.Second)
		a.logger.Verbose().Str("path", sp).Msg("writing sinf data")

		file, err := zip.Create(sp)
		if err != nil {
			return errors.Wrap(err, ErrCreateSinfFile.Error())
		}

		_, err = file.Write(pair.First.Data)
		if err != nil {
			return errors.Wrap(err, ErrWriteSinfData.Error())
		}
	}

	return nil
}

func (a *appstore) applyLegacySinfPatches(item DownloadItemResult, zip *zip.Writer, infoData []byte, appBundle string) error {
	a.logger.Verbose().Msg("applying legacy sinf patches")

	var info PackageInfo
	_, err := plist.Unmarshal(infoData, &info)
	if err != nil {
		return errors.Wrap(err, ErrUnmarshal.Error())
	}

	sp := fmt.Sprintf("Payload/%s.app/SC_Info/%s.sinf", appBundle, info.BundleExecutable)
	a.logger.Verbose().Str("path", sp).Msg("writing sinf data")

	file, err := zip.Create(sp)
	if err != nil {
		return errors.Wrap(err, ErrCreateSinfFile.Error())
	}

	_, err = file.Write(item.Sinfs[0].Data)
	if err != nil {
		return errors.Wrap(err, ErrWriteSinfData.Error())
	}

	return nil
}
