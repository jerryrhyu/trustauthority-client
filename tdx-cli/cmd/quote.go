/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-tdx"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// quoteCmd represents the quote command
var quoteCmd = &cobra.Command{
	Use:   constants.QuoteCmd,
	Short: "Fetches the TD quote",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := getQuote(cmd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(quoteCmd)
	quoteCmd.Flags().StringP(constants.NonceOption, "n", "", "Nonce in base64 encoded format")
	quoteCmd.Flags().StringP(constants.UserDataOption, "u", "", "User Data in base64 encoded format")
}

func getQuote(cmd *cobra.Command) error {

	userData, err := cmd.Flags().GetString(constants.UserDataOption)
	if err != nil {
		return err
	}

	nonce, err := cmd.Flags().GetString(constants.NonceOption)
	if err != nil {
		return err
	}

	var userDataBytes []byte
	if userData != "" {
		userDataBytes, err = base64.StdEncoding.DecodeString(userData)
		if err != nil {
			return errors.Wrap(err, "Error while base64 decoding of userdata")
		}
	}

	var nonceBytes []byte
	var verifierNonce connector.VerifierNonce
	if nonce != "" {
		nonceBytes, err = base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			return errors.Wrap(err, "Error while base64 decoding of nonce")
		}
		err = json.Unmarshal(nonceBytes, &verifierNonce)
		if err != nil {
			fmt.Println("Unmarshall error: ", err.Error())
		}
		nonceBytes = append(verifierNonce.Val, verifierNonce.Iat[:]...)
	}

	adapter, err := tdx.NewEvidenceAdapter(userDataBytes, nil)
	if err != nil {
		return errors.Wrap(err, "Error while creating tdx adapter")
	}
	evidence, err := adapter.CollectEvidence(nonceBytes)
	if err != nil {
		return errors.Wrap(err, "Failed to collect evidence")
	}

	fmt.Println("Quote:", base64.StdEncoding.EncodeToString(evidence.Evidence))
	fmt.Println("runtime_data:", base64.StdEncoding.EncodeToString(evidence.UserData))
	fmt.Println("user_data:", userData)

	return nil
}
